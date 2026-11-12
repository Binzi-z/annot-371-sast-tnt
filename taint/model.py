"""仓库级索引：函数表、import 解析、调用边。

跨过程传播的"地图"在这一层构建；引擎只通过这里解析 callee，
保证跨文件传播有明确的作用域边界（见 engine 中的有界不动点）。
"""
from __future__ import annotations

import dataclasses
from typing import Optional

from . import parser_util as pu


@dataclasses.dataclass
class FuncSummary:
    """函数摘要（不动点迭代的载体，可 JSON 序列化用于增量缓存）。

    param_tainted: 假设哪些形参带污点时进行分析（位掩码，按 params 顺序）
    returns_taint: 在上述假设下，return 值是否带污点
    cond_findings: 在"任一形参为污点"假设下成立的 sink 发现
                   （每条记录依赖哪些形参下标，0 表示不依赖形参即恒成立）
    """

    node_id: pu.NodeId
    params: tuple[str, ...]
    returns_taint: bool = False
    return_deps: tuple[int, ...] = ()
    cond_findings: list = dataclasses.field(default_factory=list)
    callees: tuple[str, ...] = ()          # 本函数体内调用到的全限定名候选
    invocations: list = dataclasses.field(default_factory=list)  # 调用点实参污点映射
    version: int = 0

    def to_cache(self) -> dict:
        return {
            "file": self.node_id.file,
            "qualname": self.node_id.qualname,
            "params": list(self.params),
            "returns_taint": self.returns_taint,
            "return_deps": list(self.return_deps),
            "cond_findings": self.cond_findings,
            "callees": list(self.callees),
            "invocations": self.invocations,
            "version": self.version,
        }

    @classmethod
    def from_cache(cls, d: dict) -> "FuncSummary":
        return cls(
            node_id=pu.NodeId(d["file"], d["qualname"]),
            params=tuple(d["params"]),
            returns_taint=d["returns_taint"],
            return_deps=tuple(d["return_deps"]),
            cond_findings=list(d["cond_findings"]),
            callees=tuple(d["callees"]),
            invocations=list(d.get("invocations", [])),
            version=d.get("version", 0),
        )


class RepoIndex:
    def __init__(self):
        self.files: dict[str, pu.ParsedFile] = {}
        self.funcs: dict[pu.NodeId, pu.FuncNode] = {}
        self.summaries: dict[pu.NodeId, FuncSummary] = {}
        # 短名 -> 定义（同模块内直接调用解析用）
        self.by_short_name: dict[str, list[pu.NodeId]] = {}
        # 文件 -> 本地名 -> (module.path, symbol)
        self.imports_by_file: dict[str, dict[str, str]] = {}
        # 反向调用边：callee -> callers，增量重算用
        self.callers: dict[pu.NodeId, set[pu.NodeId]] = {}

    def add_file(self, parsed: pu.ParsedFile) -> None:
        self.files[parsed.path] = parsed
        local_imports: dict[str, str] = {}
        for mod_path, alias in parsed.imports:
            if alias is not None:
                local_imports[alias] = mod_path
            else:
                local_imports[mod_path.split(".")[0]] = mod_path
                if "." in mod_path:
                    local_imports[mod_path.rsplit(".", 1)[1]] = mod_path
        self.imports_by_file[parsed.path] = local_imports
        for fn in parsed.funcs:
            self.funcs[fn.node_id] = fn
            short = fn.qualname.split(".")[-1]
            self.by_short_name.setdefault(short, []).append(fn.node_id)
            self.summaries.setdefault(
                fn.node_id, FuncSummary(fn.node_id, fn.params)
            )

    # ------------------------------------------------------------ 解析 callee

    def resolve_callee(self, caller_file: str, chain: list[str]) -> Optional[pu.NodeId]:
        """把调用点的名字点链解析到仓库内函数定义；找不到返回 None。

        解析顺序：import 别名 → 同文件函数 → 仓库内同名函数（保守回退）。
        """
        if not chain:
            return None
        head, rest = chain[0], chain[1:]
        imports = self.imports_by_file.get(caller_file, {})

        # 1) import 绑定
        if head in imports:
            mod_path = imports[head]
            if rest:
                # from a.b import c ; c.d(...) -> a.b.c.d
                target = mod_path + "." + ".".join(rest)
            else:
                # import a.b / from a.b import c —— 两种都可能
                target = mod_path
            got = self._match_qualname(target, caller_file)
            if got is not None:
                return got

        # 2) 同文件直接调用（含嵌套函数，取最内层匹配）
        same_file = [nid for nid in self.by_short_name.get(head, [])
                     if nid.file == caller_file]
        if same_file:
            if rest:
                # 类方法 self.foo() 之类：忽略属性段，按短名回退
                return same_file[-1]
            return same_file[-1]

        # 3) 仓库全局同名回退（唯一时才采用，避免乱连边导致爆炸）
        candidates = self.by_short_name.get(head, [])
        if len(candidates) == 1 and not rest:
            return candidates[0]
        return None

    def _match_qualname(self, target: str, caller_file: str) -> Optional[pu.NodeId]:
        # target 可能是模块路径.函数名；文件名即模块名（语料扁平结构）
        target_mod, _, fn = target.rpartition(".")
        mod_file = target_mod.replace(".", "/") + ".py" if target_mod else ""
        for nid in self.by_short_name.get(fn, []):
            if mod_file and nid.file.endswith(mod_file):
                return nid
            if not target_mod and nid.file == caller_file:
                return nid
        # 扁平仓库：模块名 == 文件 stem
        if target_mod:
            stem = target_mod.rsplit(".", 1)[-1] + ".py"
            for nid in self.by_short_name.get(fn, []):
                if nid.file.endswith("/" + stem) or nid.file == stem:
                    return nid
        return None

    def register_call(self, caller: pu.NodeId, callee: pu.NodeId) -> None:
        self.callers.setdefault(callee, set()).add(caller)
