"""污点分析引擎。

设计要点（爆炸半径控制见 README「跨过程传播的爆炸半径」一节）：

1. 过程内：流敏感的环境模拟（变量 -> Taint），支持赋值、字段/下标、集合、
   二元运算、f-string、调用返回值；if 验证守卫在作用域内清除污点。
2. 过程间：上下文不敏感的函数摘要不动点。每个函数只分析一次/轮，
   摘要只有「返回值是否带污点 + 依赖哪些形参」和「条件性 sink 发现」两类，
   不展开调用栈、不克隆上下文，因此复杂度 O(函数数 × 轮数)。
3. 硬边界：跨过程深度上限、每轮函数重分析上限、字段/下标不无限展开
   （统一折叠为根变量的污点）、SCC 环上版本号收敛即停。
"""
from __future__ import annotations

import dataclasses
from typing import Optional

from . import parser_util as pu
from . import rules
from .model import FuncSummary, RepoIndex

# 跨过程不动点硬上限
MAX_FIXPOINT_ROUNDS = 6
MAX_REANALYZES_PER_FUNC = 4
# 单函数语句访问上限（防止异常 AST 造成局部放大）
STMT_BUDGET = 20000


@dataclasses.dataclass(frozen=True)
class Taint:
    """污点状态：是否脏 + 依赖的根变量集合（用于守卫精确清除）。"""

    tainted: bool = False
    roots: frozenset[str] = frozenset()

    @classmethod
    def clean(cls) -> "Taint":
        return cls(False, frozenset())

    @classmethod
    def dirty(cls, roots) -> "Taint":
        roots = frozenset(roots)
        return cls(bool(roots), roots)


def merge_taint(a: Taint, b: Taint) -> Taint:
    return Taint(a.tainted or b.tainted, a.roots | b.roots)


@dataclasses.dataclass
class Finding:
    file: str
    line: int
    end_line: int
    kind: str
    func: str
    evidence: str
    deps: tuple            # 依赖的形参下标；空元组表示恒成立
    trace: tuple           # 跨函数传播链（函数限定名），用于解释结果

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "sink": self.kind,
            "func": self.func,
            "evidence": self.evidence,
            "deps": list(self.deps),
            "trace": list(self.trace),
        }


class _Scope:
    """函数内一次分析的可变状态。"""

    def __init__(self, index: RepoIndex, file: pu.ParsedFile, func_id: pu.NodeId,
                 param_taint: dict[str, Taint], trace: tuple, depth: int):
        self.index = index
        self.file = file
        self.func_id = func_id
        self.env: dict[str, Taint] = dict(param_taint)
        # 激活的验证守卫：root 变量 -> 守卫类型
        self.guards: dict[str, str] = {}
        self.findings: list[Finding] = []
        self.returns_taint = False
        self.return_deps: set[int] = set()
        self.trace = trace
        self.depth = depth
        self.budget = STMT_BUDGET
        # 形参名 -> 下标（记录 deps 用）
        self.param_index = {p: i for i, p in enumerate(index.funcs[func_id].params)}
        # 本函数内对用户自定义函数的调用（含实参污点映射），最终阶段统一实例化
        self.callee_invocations: list[dict] = []

    # ------------------------------------------------------------- 环境读写

    def get(self, name: str) -> Taint:
        return self.env.get(name, Taint.clean())

    def set_root(self, name: str, t: Taint) -> None:
        # 字段/下标折叠：x.a / x[k] 都更新根 x 的污点
        self.env[name] = t

    def effective_taint(self, t: Taint) -> Taint:
        """应用激活守卫：被保护的 root 污点在此作用域内视为干净。"""
        if not t.tainted:
            return t
        alive = frozenset(r for r in t.roots if r not in self.guards)
        return Taint(bool(alive), alive)

    def taint_for_sink(self, t: Taint, sink_kind: str) -> Taint:
        """按 sink 类型应用守卫：只有匹配该 sink 防护意图的守卫才能清除污点。

        - path-prefix 只防护 path sink；
        - host-prefix 只防护 ssrf sink；
        - allowlist（isalnum/正则/成员白名单）防护 cmdi/sqli/ssrf/path。
        """
        if not t.tainted:
            return t
        alive = set()
        for r in t.roots:
            g = self.guards.get(r)
            if g is None:
                alive.add(r)
            elif g == "path-prefix" and sink_kind != "path":
                alive.add(r)
            elif g == "host-prefix" and sink_kind != "ssrf":
                alive.add(r)
            # allowlist 对所有 sink 生效；匹配类型的专用守卫清除污点
        return Taint(bool(alive), frozenset(alive))


# ============================================================ 表达式污点求值

class Evaluator:
    def __init__(self, scope: _Scope):
        self.s = scope

    def eval(self, node) -> Taint:
        if node is None:
            return Taint.clean()
        t = node.type
        if t == "identifier":
            return self.s.effective_taint(self.s.get(node.text.decode()))
        if t in ("integer", "float", "string", "true", "false", "none", "comment"):
            # f-string 在 tree-sitter 里仍是 string，需单独看插值
            return self._string_taint(node)
        if t in ("list", "tuple", "set", "dictionary", "parenthesized_expression"):
            return self._container(node)
        if t == "binary_operator":
            return self._binary(node)
        if t == "boolean_operator":
            return self._bool_op(node)
        if t in ("not_operator", "unary_operator"):
            arg = node.child_by_field_name("argument")
            return self.eval(arg)
        if t == "comparison_operator":
            skip = {"<", ">", "==", "!=", "<=", ">=", "in", "not", "is"}
            parts = [c for c in node.named_children if c.type not in skip]
            return self._join(parts)
        if t == "conditional_expression":
            return self._ternary(node)
        if t == "subscript":
            return self._subscript(node)
        if t == "attribute":
            return self._attribute(node)
        if t == "call":
            return self._call(node)
        if t == "lambda":
            return Taint.clean()
        if t in ("list_comprehension", "set_comprehension", "dictionary_comprehension",
                 "generator_expression"):
            return self._comprehension(node)
        if t == "await":
            return self.eval(node.child_by_field_name("argument"))
        if t == "yield":
            arg = node.child_by_field_name("argument")
            return self.eval(arg) if arg is not None else Taint.clean()
        # 未知表达式：保守地合并子节点污点
        return self._join(node.children)

    def _string_taint(self, node) -> Taint:
        if node.type != "string":
            return Taint.clean()
        # f-string：含 interpolation 节点；普通字符串字面量干净
        parts = [c for c in node.children if c.type == "interpolation"]
        if not parts:
            return Taint.clean()
        return self._join([p.child_by_field_name("expression")
                           or p.named_children[0] for p in parts])

    def _container(self, node) -> Taint:
        children = []
        for ch in node.children:
            if ch.type in ("{", "}", "[", "]", "(", ")", ","):
                continue
            if ch.type == "pair":
                children.append(ch.child_by_field_name("value"))
            elif ch.type == "keyword_argument":
                children.append(ch.child_by_field_name("value"))
            else:
                children.append(ch)
        return self._join(children)

    def _binary(self, node) -> Taint:
        left_n = pu.child(node, "left", 0)
        right_n = pu.child(node, "right", 1)
        left = self.eval(left_n)
        rt = self.eval(right_n)
        # 乘法 "x" * n 之类：数字乘数不传播，其余合并
        op = node.child_by_field_name("operator")
        if op is not None and op.text == b"*" and right_n is not None and right_n.type in ("integer", "float"):
            return left
        return merge_taint(left, rt)

    def _bool_op(self, node) -> Taint:
        return self._join([c for c in node.named_children if c.type not in ("and", "or")])

    def _ternary(self, node) -> Taint:
        return merge_taint(
            self.eval(pu.child(node, "consequence", 1)),
            self.eval(pu.child(node, "alternative", 2)),
        )

    def _subscript(self, node) -> Taint:
        # x[k] 的污点折叠到根 x；下标本身的污点也并入（如 d[tainted_key]）
        obj = pu.child(node, "object", 0)
        idx = pu.child(node, "index", 1)
        return merge_taint(self.eval(obj), self.eval(idx))

    def _attribute(self, node) -> Taint:
        # 字段污点折叠到根对象（字段敏感性通过 roots 保留守卫能力）
        return self.eval(pu.child(node, "object", 0))

    def _comprehension(self, node) -> Taint:
        # 主体表达式 + 迭代源有污点则结果可能带污点
        body = node.child_by_field_name("body") or node.named_children[0]
        vals = [body]
        for ch in node.named_children:
            if ch.type in ("for_in_clause", "for_in_statement"):
                it = ch.child_by_field_name("iterable") or ch.child_by_field_name("right")
                if it is not None:
                    vals.append(it)
        return self._join(vals)

    def _join(self, nodes) -> Taint:
        acc = Taint.clean()
        for n in nodes:
            if n is not None:
                acc = merge_taint(acc, self.eval(n))
        return acc

    # ------------------------------------------------------------- 调用

    def _call(self, node) -> Taint:
        chain = pu.call_name(node)
        args = pu.call_args(node)

        # 1) 显式源
        if rules.explicit_source(node):
            return Taint.dirty(["<source>"])

        # 2) sanitizer 白名单：净化调用的返回值干净
        if rules.is_sanitizer_call(node):
            return Taint.clean()

        # 3) 内置/库函数的污点建模
        builtin = _builtin_call_taint(node, chain, args, self)
        if builtin is not None:
            return builtin

        # 4) 用户自定义函数：查摘要（上下文不敏感）
        callee = self.s.index.resolve_callee(self.s.file.path, chain) if chain else None
        if callee is not None:
            return self._user_call(node, callee, chain, args)

        # 5) 未知函数：参数脏 -> 返回值保守视为脏
        return self._join(args)

    def _user_call(self, node, callee, chain, args) -> Taint:
        idx = self.s.index
        summary = idx.summaries.get(callee)
        arg_taints = [self.eval(a) for a in args]

        # 记录"本次调用中哪些形参位置收到了污点"，供最终阶段实例化 callee 内部 sink。
        # 不在调用点直接发 finding —— 那样同一 callee sink 会在每个 caller 重复。
        if summary is not None:
            dirty_deps = tuple(sorted({
                d for d, t in enumerate(arg_taints) if t.tainted
            }))
            self.s.callee_invocations.append({
                "callee": str(callee),
                "line": pu.start_line(node),
                "dirty_deps": dirty_deps,
                "arg_roots": tuple(sorted({r for t in arg_taints if t.tainted for r in t.roots})),
            })
            # 返回值
            if summary.returns_taint:
                roots = set()
                for d in summary.return_deps:
                    if d < len(arg_taints) and arg_taints[d].tainted:
                        roots |= arg_taints[d].roots
                if roots:
                    return Taint.dirty(roots)
            return Taint.clean()
        # 摘要未就绪（首轮）：保守按实参合并
        return self._join(args)


# 内置/库函数的轻量建模表
def _builtin_call_taint(node, chain, args, ev: Evaluator) -> Optional[Taint]:
    if not chain:
        return None
    name = chain[-1]
    # 方法接收者污点（x.method(...) 里的 x）
    func_node = node.child_by_field_name("function")
    receiver = Taint.clean()
    if func_node is not None and func_node.type == "attribute":
        receiver = ev.eval(pu.child(func_node, "object", 0))
    # 不产生新污点的纯函数（显式列举，避免未知函数放大）
    PURE = {"len", "int", "float", "bool", "type", "isinstance"}
    if name in PURE:
        return Taint.clean()
    if name in ("str", "repr"):
        # 字符串化不净化
        return ev._join(args)
    if name in ("list", "tuple", "set", "dict", "frozenset"):
        return ev._join(args)
    if name in ("map", "filter"):
        return ev._join(args[1:])
    if name == "enumerate":
        return ev.eval(args[0]) if args else Taint.clean()
    if name == "zip":
        return ev._join(args)
    if name == "get":
        # dict.get(k, default)：折叠为字典根 + 默认值
        return merge_taint(receiver, ev._join(args))
    if name in ("append", "extend", "add", "update", "insert"):
        return None  # 容器写方法交给语句层处理
    if name == "join":
        # sep.join(iterable)：接收者与迭代源任一脏即脏
        return merge_taint(receiver, ev._join(args))
    if name == "format":
        # "...".format(x)：接收者与参数任一脏即脏
        return merge_taint(receiver, ev._join(args))
    if name in ("strip", "lstrip", "rstrip", "lower", "upper", "replace",
                "split", "rsplit", "encode", "decode"):
        # 字符串变形不净化：接收者 + 参数
        return merge_taint(receiver, ev._join(args))
    return None


# ============================================================ 语句层

class Engine:
    def __init__(self, index: RepoIndex):
        self.index = index
        self.reanalyze_count: dict[pu.NodeId, int] = {}

    def analyze_function(self, func_id: pu.NodeId) -> FuncSummary:
        fn = self.index.funcs[func_id]
        parsed = self.index.files[func_id.file]
        # 假设所有形参都是污点源（服务层入口边界策略）
        param_taint = {
            p: Taint.dirty([p]) for p in fn.params
        }
        scope = _Scope(self.index, parsed, func_id, param_taint, (str(func_id),), 0)
        ev = Evaluator(scope)
        self._walk_block(fn.body, scope, ev)

        summary = self.index.summaries[func_id]
        cond = []
        for f in scope.findings:
            cond.append({
                "kind": f.kind,
                "line": f.line,
                "end_line": f.end_line,
                "evidence": f.evidence,
                "deps": list(f.deps),
                "trace": list(f.trace),
            })
        new_summary = FuncSummary(
            node_id=func_id,
            params=fn.params,
            returns_taint=scope.returns_taint,
            return_deps=tuple(sorted(scope.return_deps)),
            cond_findings=cond,
            callees=summary.callees,
            invocations=list(scope.callee_invocations),
            version=summary.version + 1,
        )
        self.index.summaries[func_id] = new_summary
        return new_summary

    # ------------------------------------------------------------- 块遍历

    def _walk_block(self, block, scope: _Scope, ev: Evaluator) -> None:
        for stmt in block.children:
            if scope.budget <= 0:
                return
            scope.budget -= 1
            self._stmt(stmt, scope, ev)

    def _stmt(self, stmt, scope: _Scope, ev: Evaluator) -> None:
        t = stmt.type
        if t == "assignment":
            self._assignment(stmt, scope, ev)
        elif t in ("augmented_assignment",):
            self._aug_assignment(stmt, scope, ev)
        elif t == "expression_statement":
            self._expr_stmt(stmt, scope, ev)
        elif t in ("call", "await"):
            # tree-sitter python：块内裸调用没有 expression_statement 包裹
            self._check_sinks(stmt, scope, ev)
            ev.eval(stmt)
        elif t == "return_statement":
            self._return(stmt, scope, ev)
        elif t == "if_statement":
            self._if(stmt, scope, ev)
        elif t in ("for_statement", "for_in_clause", "while_statement", "while_clause"):
            self._loop(stmt, scope, ev)
        elif t == "with_statement":
            self._with(stmt, scope, ev)
        elif t == "try_statement":
            self._try(stmt, scope, ev)
        elif t == "function_definition":
            self._nested_func(stmt, scope, ev)
        elif t in ("raise_statement", "pass_statement", "break_statement",
                   "continue_statement", "import_statement", "import_from_statement",
                   "global_statement", "nonlocal_statement", "decorated_definition",
                   "assert_statement", "delete_statement", "type_alias_statement"):
            if t == "assert_statement":
                self._assert_guard(stmt, scope, ev)
        # 其余声明类语句忽略

    # ------------------------------------------------------------- 赋值

    def _assignment(self, stmt, scope, ev) -> None:
        rhs = stmt.child_by_field_name("right")
        self._check_sinks(rhs, scope, ev)
        rhs_t = ev.eval(rhs)
        for target in stmt.children:
            if target.type in ("=", "type"):
                continue
            self._bind(target, rhs_t, scope, ev)

    def _aug_assignment(self, stmt, scope, ev) -> None:
        lhs = stmt.child_by_field_name("left")
        rhs = stmt.child_by_field_name("right")
        self._check_sinks(rhs, scope, ev)
        t = merge_taint(ev.eval(lhs), ev.eval(rhs))
        self._bind(lhs, t, scope, ev)

    def _bind(self, target, taint: Taint, scope, ev) -> None:
        if target.type == "identifier":
            scope.set_root(target.text.decode(), taint)
        elif target.type in ("attribute", "subscript"):
            # x.a = v / x[k] = v：折叠到根 x，且合并（容器可能已有脏元素）
            obj = target.child_by_field_name("object")
            root = _root_name(obj)
            if root is not None:
                prev = scope.get(root)
                scope.set_root(root, merge_taint(prev, taint))
        elif target.type in ("list", "tuple", "pattern_list"):
            # 解包：每个元素独立绑定
            vals = [c for c in target.named_children if c.type not in (",", "[", "]", "(", ")")]
            for v in vals:
                self._bind(v, taint, scope, ev)
        elif target.type == "tuple_pattern":
            for v in target.named_children:
                self._bind(v, taint, scope, ev)

    def _expr_stmt(self, stmt, scope, ev) -> None:
        expr = stmt.child_by_field_name("expression")
        if expr is None:
            return
        # sink 检查在调用求值时通过 _check_sinks 统一做
        self._check_sinks(expr, scope, ev)
        taint = ev.eval(expr)
        # 容器写方法 x.append(tainted)：把污点并回容器根
        if expr.type == "call":
            chain = pu.call_name(expr)
            if chain and chain[-1] in ("append", "extend", "add", "update", "insert"):
                func = expr.child_by_field_name("function")
                if func is not None and func.type == "attribute":
                    root = _root_name(func.child_by_field_name("object"))
                    if root is not None:
                        scope.set_root(root, merge_taint(scope.get(root), taint))

    def _return(self, stmt, scope, ev) -> None:
        val = stmt.child_by_field_name("argument")
        if val is None:
            # 兼容 grammar：return_statement 的命名子节点即返回值
            val = pu.first_named_child(stmt)
        if val is not None:
            self._check_sinks(val, scope, ev)
        t = ev.eval(val) if val is not None else Taint.clean()
        if t.tainted:
            scope.returns_taint = True
            for r in t.roots:
                if r in scope.param_index:
                    scope.return_deps.add(scope.param_index[r])

    # ------------------------------------------------------------- 控制流

    def _if(self, stmt, scope, ev) -> None:
        cond = stmt.child_by_field_name("condition")
        body = stmt.child_by_field_name("consequence")
        if cond is None or body is None:
            named = stmt.named_children
            cond = cond or named[0]
            body = body or next((c for c in named if c.type == "block"), None)

        # 先在条件上做 sink 检查（条件里也可能有危险调用）
        self._check_sinks(cond, scope, ev)

        guard = rules.extract_guard(stmt, scope.file.text_bytes)
        terminating = rules._terminating(body)
        added_guards: list[str] = []
        if guard is not None and terminating:
            # 拒绝分支终止：守卫在 if 之后继续生效（这是白名单校验的核心语义）
            for r in guard.roots:
                if r not in scope.guards:
                    scope.guards[r] = guard.kind
                    added_guards.append(r)

        self._walk_block(body, scope, ev)
        if not terminating:
            # 非终止型 if：守卫仅在块内有效，出块即撤销
            for r in added_guards:
                scope.guards.pop(r, None)

        # elif_clause / else_clause / 旧式 alternative
        alt = stmt.child_by_field_name("alternative")
        candidates = [alt] if alt is not None else [
            c for c in stmt.named_children if c.type in ("elif_clause", "else_clause")
        ]
        for cl in candidates:
            if cl is None:
                continue
            if cl.type == "elif_clause":
                # 包成临时 if 形态：条件 + block
                sub_cond = cl.child_by_field_name("condition") or cl.named_children[0]
                sub_body = next((c for c in cl.named_children if c.type == "block"), None)
                self._check_sinks(sub_cond, scope, ev)
                if sub_body is not None:
                    self._walk_block(sub_body, scope, ev)
                sub_alt = next((c for c in cl.named_children
                                if c.type in ("elif_clause", "else_clause")), None)
                if sub_alt is not None and sub_alt.type == "else_clause":
                    b = next((c for c in sub_alt.named_children if c.type == "block"), None)
                    if b is not None:
                        self._walk_block(b, scope, ev)
            elif cl.type == "else_clause":
                b = next((c for c in cl.named_children if c.type == "block"), None)
                if b is not None:
                    self._walk_block(b, scope, ev)
            elif cl.type == "if_statement":
                self._if(cl, scope, ev)
            else:
                self._walk_block(cl, scope, ev)

    def _assert_guard(self, stmt, scope, ev) -> None:
        # assert x.isalnum() 不作为可靠守卫（python -O 会移除），仅检查 sink
        cond = stmt.child_by_field_name("condition")
        if cond is not None:
            self._check_sinks(cond, scope, ev)

    def _loop(self, stmt, scope, ev) -> None:
        if stmt.type in ("for_statement", "for_in_clause"):
            target = stmt.child_by_field_name("left")
            iterable = stmt.child_by_field_name("right")
            if iterable is None:
                # 回退：第二个命名子节点为迭代源
                named = stmt.named_children
                iterable = named[1] if len(named) > 1 else None
                target = target or named[0]
            if iterable is not None:
                self._check_sinks(iterable, scope, ev)
                t = ev.eval(iterable)
                if target is not None and t.tainted:
                    self._bind(target, t, scope, ev)
        else:  # while
            cond = stmt.child_by_field_name("condition")
            if cond is not None:
                self._check_sinks(cond, scope, ev)
        body = stmt.child_by_field_name("body")
        if body is not None:
            # 循环体只走一遍（摘要不动点靠轮间迭代收敛，避免局部放大）
            self._walk_block(body, scope, ev)

    def _with(self, stmt, scope, ev) -> None:
        body = stmt.child_by_field_name("body")
        # with_statement -> with_clause -> with_item(as_pattern)
        clauses = [c for c in stmt.named_children if c.type in ("with_clause", "with_item")]
        items = []
        for cl in clauses:
            if cl.type == "with_clause":
                items.extend(c for c in cl.named_children if c.type == "with_item")
            else:
                items.append(cl)
        for item in items:
            # as_pattern: value 是被调表达式，as_pattern_target 是绑定名
            ap = item if item.type == "as_pattern" else None
            ctx_node = item
            as_name = None
            if ap is not None:
                ctx_node = ap.child_by_field_name("value") or ap.named_children[0]
                tgt = ap.child_by_field_name("target") or next(
                    (c for c in ap.named_children if c.type == "as_pattern_target"), None)
                as_name = tgt
            if ctx_node is not None:
                self._check_sinks(ctx_node, scope, ev)
                if as_name is not None:
                    self._bind(as_name, ev.eval(ctx_node), scope, ev)
        if body is not None:
            self._walk_block(body, scope, ev)

    def _try(self, stmt, scope, ev) -> None:
        for ch in stmt.children:
            if ch.type == "block":
                self._walk_block(ch, scope, ev)
            elif ch.type in ("except_clause", "finally_clause"):
                body = ch.child_by_field_name("body")
                if body is not None:
                    self._walk_block(body, scope, ev)

    def _nested_func(self, stmt, scope, ev) -> None:
        # 嵌套函数：注册到索引，独立参与不动点；当前作用域不展开它
        name = stmt.child_by_field_name("name")
        if name is not None:
            # 已在 parse 阶段收集，这里跳过即可
            pass

    # ------------------------------------------------------------- sink 检查

    def _check_sinks(self, node, scope: _Scope, ev: Evaluator) -> None:
        """递归找出表达式内所有 sink 调用，按实参污点 + 守卫决定是否报。"""
        for sub in _walk_calls(node):
            hit = rules.match_sink(sub)
            if hit is None:
                continue
            arg_t = ev.eval(hit.arg_node)
            arg_t = scope.taint_for_sink(arg_t, hit.kind)
            if not arg_t.tainted:
                continue
            # 路径 sink 的额外净化判定：realpath 结果且有前缀守卫
            if self._path_sanitized(sub, hit, scope, ev):
                continue
            # SQL 参数化二次确认（规则层已拦，双保险）
            if hit.kind == "sqli" and self._sql_parameterized(sub):
                continue
            deps = tuple(sorted({
                scope.param_index[r] for r in arg_t.roots if r in scope.param_index
            }))
            key = (hit.kind, pu.start_line(sub))
            if any((f.kind, f.line) == key for f in scope.findings):
                continue
            scope.findings.append(Finding(
                file=scope.file.path,
                line=pu.start_line(sub),
                end_line=sub.end_point[0] + 1,
                kind=hit.kind,
                func=str(scope.func_id),
                evidence=pu.node_text(sub, scope.file.text_bytes).strip()[:200],
                deps=deps,
                trace=scope.trace,
            ))

    def _sql_parameterized(self, call_node) -> bool:
        args = pu.call_args(call_node)
        return len(args) >= 2

    def _path_sanitized(self, call_node, hit: rules.SinkHit, scope, ev) -> bool:
        # open(path) 且 path 来自 realpath/abspath，且该根变量有 path-prefix 守卫
        t = ev.eval(hit.arg_node)
        for r in t.roots:
            if scope.guards.get(r) == "path-prefix":
                return True
        return False


def _walk_calls(node):
    if node.type == "call":
        yield node
    for ch in node.named_children:
        yield from _walk_calls(ch)


def _root_name(node) -> Optional[str]:
    if node is None:
        return None
    cur = node
    while cur is not None and cur.type in ("attribute", "subscript"):
        cur = cur.child_by_field_name("object")
    if cur is not None and cur.type == "identifier":
        return cur.text.decode()
    return None


# ============================================================ 跨过程不动点

def run_fixpoint(index: RepoIndex, logger=print, skip_ids: Optional[set] = None) -> dict:
    """上下文不敏感的摘要不动点。

    skip_ids 中的函数（增量缓存命中、摘要已恢复）不重新分析，
    但仍参与调用边构建，保证变更函数的跨文件传播不中断。
    返回统计信息。每轮按调用边传播变化；函数重分析次数与总轮数都有硬上限。
    """
    skip_ids = skip_ids or set()
    engine = Engine(index)
    # 先建调用边（一次性、静态；跳过的函数无 AST 句柄，无法枚举调用点）
    for nid, fn in list(index.funcs.items()):
        if nid in skip_ids or fn.body is None:
            continue
        for call in _walk_calls(fn.body):
            chain = pu.call_name(call)
            if not chain:
                continue
            callee = index.resolve_callee(nid.file, chain)
            if callee is not None and callee != nid:
                index.register_call(nid, callee)
                s = index.summaries[nid]
                if str(callee) not in s.callees:
                    s.callees = s.callees + (str(callee),)

    # 首轮：只分析未命中缓存的函数
    worklist = [nid for nid in index.funcs if nid not in skip_ids]
    rounds = 0
    total_analyzes = 0
    while worklist and rounds < MAX_FIXPOINT_ROUNDS:
        rounds += 1
        current = worklist
        worklist = []
        changed = set()
        for nid in current:
            if nid in skip_ids:
                continue
            if engine.reanalyze_count.get(nid, 0) >= MAX_REANALYZES_PER_FUNC:
                continue
            before = index.summaries[nid]
            before_sig = _sig(before)
            engine.analyze_function(nid)
            total_analyzes += 1
            engine.reanalyze_count[nid] = engine.reanalyze_count.get(nid, 0) + 1
            if _sig(index.summaries[nid]) != before_sig:
                changed.add(nid)
        # 变化沿反向调用边传播；跳过的函数摘要视为稳定，不再重算
        for nid in changed:
            for caller in index.callers.get(nid, ()):  # type: ignore[arg-type]
                if caller in skip_ids:
                    continue
                if caller not in worklist:
                    worklist.append(caller)
        logger(f"[fixpoint] round={rounds} changed={len(changed)} "
               f"next_worklist={len(worklist)} analyzes={total_analyzes}")

    return {
        "rounds": rounds,
        "total_analyzes": total_analyzes,
        "func_count": len(index.funcs),
        "skipped": len(skip_ids),
        "capped": rounds >= MAX_FIXPOINT_ROUNDS and bool(worklist),
    }


def _sig(s: FuncSummary) -> tuple:
    return (
        s.returns_taint,
        s.return_deps,
        tuple((c["kind"], c["line"], tuple(c.get("deps", []))) for c in s.cond_findings),
    )


# ============================================================ 最终实例化

def instantiate_findings(index: RepoIndex) -> list[Finding]:
    """不动点收敛后，把条件性 sink 按"入口形参是否能收到污点"实例化。

    入口策略：仓库内所有函数的形参都视为潜在不可信输入（服务层边界），
    因此直接 sink（deps 命中本函数形参）恒成立；跨函数 sink 沿调用边
    检查实参污点映射。深度受 MAX_INSTANTIATE_DEPTH 限制。
    """
    MAX_INSTANTIATE_DEPTH = 8
    findings: list[Finding] = []

    # node_id 字符串 -> NodeId
    id_by_str = {str(nid): nid for nid in index.funcs}

    def emit(nid: pu.NodeId, cf: dict, trace: tuple) -> None:
        key = (nid.file, cf["line"], cf["kind"])
        full_trace = trace + (str(nid),)
        # 同一 sink 可能被多个入口到达：保留最长传播链，便于人工研判
        prev = best_trace.get(key)
        if prev is None or len(full_trace) > len(prev):
            best_trace[key] = full_trace
            best_cf[key] = (nid, cf)

    best_trace: dict[tuple, tuple] = {}
    best_cf: dict[tuple, tuple] = {}

    def reachable(nid_str: str, dirty_params: frozenset, depth: int, path: tuple) -> None:
        if depth > MAX_INSTANTIATE_DEPTH:
            return
        nid = id_by_str.get(nid_str)
        if nid is None:
            return
        summary = index.summaries.get(nid)
        if summary is None:
            return
        # 本函数内部 sink：依赖的形参收到污点即触发（deps 为空 = 恒成立）
        for cf in summary.cond_findings:
            deps = frozenset(d for d in cf.get("deps", []) if isinstance(d, int))
            if not deps or (deps & dirty_params):
                emit(nid, cf, path)
        # 向下游调用传播：只沿"实参确实带污点"的调用边前进
        for inv in summary.invocations:
            callee_str = inv["callee"]
            callee_dirty = frozenset(inv.get("dirty_deps", ()))
            if not callee_dirty:
                continue
            if callee_str in path:  # 递归环：截断
                continue
            reachable(callee_str, callee_dirty, depth + 1, path + (nid_str,))

    # 每个函数作为入口启动一次（形参全部视为脏）
    for nid in index.funcs:
        summary = index.summaries[nid]
        entry_dirty = frozenset(range(len(summary.params)))
        reachable(str(nid), entry_dirty, 0, ())

    for key, (nid, cf) in sorted(best_cf.items()):
        findings.append(Finding(
            file=nid.file,
            line=cf["line"],
            end_line=cf.get("end_line", cf["line"]),
            kind=cf["kind"],
            func=str(nid),
            evidence=cf.get("evidence", ""),
            deps=tuple(cf.get("deps", [])),
            trace=best_trace[key],
        ))
    findings.sort(key=lambda f: (f.file, f.line, f.kind))
    return findings
