"""tree-sitter 封装与 AST 节点工具。

只依赖 tree-sitter / tree-sitter-language-pack 两个语法解析库，
不引入任何现成 SAST 规则。
"""
from __future__ import annotations

import dataclasses
from typing import Iterable, Optional

from tree_sitter_language_pack import get_parser

_PARSER = get_parser("python")


@dataclasses.dataclass(frozen=True)
class NodeId:
    """函数在仓库内的逻辑标识（文件相对路径 + 全限定名）。"""

    file: str
    qualname: str

    def __str__(self) -> str:
        return f"{self.file}::{self.qualname}"


@dataclasses.dataclass
class FuncNode:
    """一个函数定义的轻量模型（AST 句柄 + 结构性元数据）。"""

    node_id: NodeId
    node: object  # tree_sitter.Node
    params: tuple[str, ...]
    body: object  # tree_sitter.Node(block)
    qualname: str
    class_name: Optional[str]


@dataclasses.dataclass
class ParsedFile:
    path: str               # 相对仓库根的 posix 路径
    text_bytes: bytes
    tree: object
    funcs: list[FuncNode]
    imports: list[tuple[str, Optional[str]]]  # (模块点路径, 本地别名)
    has_error: bool


def parse_file(rel_path: str, text_bytes: bytes) -> ParsedFile:
    """解析单个 Python 文件，抽取函数定义与 import。"""
    tree = _PARSER.parse(text_bytes)
    funcs: list[FuncNode] = []
    imports: list[tuple[str, Optional[str]]] = []
    _collect(tree.root_node, rel_path, (), None, funcs)
    _collect_imports(tree.root_node, imports)
    has_error = tree.root_node.has_error
    return ParsedFile(rel_path, text_bytes, tree, funcs, imports, has_error)


def quick_structure(rel_path: str, text_bytes: bytes,
                    cached_params: dict[str, list[str]]) -> ParsedFile:
    """增量缓存命中时的轻量恢复：不做完整 AST 遍历，
    只用缓存里的形参/函数名重建函数索引（fixpoint 需要函数表与调用边元数据）。"""
    funcs: list[FuncNode] = []
    for qualname, params in cached_params.items():
        nid = NodeId(rel_path, qualname)
        class_name = qualname.rsplit(".", 1)[0] if "." in qualname else None
        funcs.append(FuncNode(
            node_id=nid, node=None, params=tuple(params),
            body=None, qualname=qualname, class_name=class_name,
        ))
    return ParsedFile(rel_path, text_bytes, None, funcs, [], False)


def _collect(node, rel_path, scope, class_name, out):
    """深度优先收集函数定义；scope 是外层函数限定名元组，支持嵌套函数。"""
    t = node.type
    if t == "function_definition":
        name_node = node.child_by_field_name("name")
        params = _param_names(node)
        body = node.child_by_field_name("body")
        qual = ".".join(scope + (name_node.text.decode(),))
        nid = NodeId(rel_path, qual)
        out.append(FuncNode(nid, node, params, body, qual, class_name))
        inner_scope = scope + (name_node.text.decode(),)
        for ch in body.children:
            _collect(ch, rel_path, inner_scope, None, out)
        return
    if t == "class_definition":
        cname = node.child_by_field_name("name").text.decode()
        body = node.child_by_field_name("body")
        for ch in body.children:
            _collect(ch, rel_path, scope, cname, out)
        return
    for ch in node.children:
        _collect(ch, rel_path, scope, class_name, out)


def _param_names(func_node) -> tuple[str, ...]:
    pn = func_node.child_by_field_name("parameters")
    names: list[str] = []
    if pn is None:
        return tuple()
    for ch in pn.children:
        # identifier / typed_parameter / default_parameter / optional_type / ...
        if ch.type == "identifier":
            names.append(ch.text.decode())
        elif ch.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
            ident = ch.child_by_field_name("name") or _first_identifier(ch)
            if ident is not None:
                names.append(ident.text.decode())
        elif ch.type in ("list_splat_pattern", "dictionary_splat_pattern"):
            ident = _first_identifier(ch)
            if ident is not None:
                names.append(ident.text.decode())
    return tuple(names)


def _first_identifier(node):
    for ch in node.children:
        if ch.type == "identifier":
            return ch
        got = _first_identifier(ch)
        if got is not None:
            return got
    return None


def _collect_imports(root, out):
    for node in _walk(root):
        if node.type == "import_statement":
            for ch in node.children:
                if ch.type == "dotted_name":
                    out.append((ch.text.decode(), None))
                elif ch.type == "aliased_import":
                    mod = ch.child_by_field_name("name").text.decode()
                    alias = ch.child_by_field_name("alias").text.decode()
                    out.append((mod, alias))
        elif node.type == "import_from_statement":
            mod_node = node.child_by_field_name("module_name")
            module = mod_node.text.decode() if mod_node is not None else ""
            for ch in node.children:
                if ch.type == "dotted_name" and ch is not mod_node:
                    out.append((f"{module}.{ch.text.decode()}", ch.text.decode()))
                elif ch.type == "aliased_import":
                    name = ch.child_by_field_name("name").text.decode()
                    alias = ch.child_by_field_name("alias").text.decode()
                    out.append((f"{module}.{name}", alias))


def _walk(node) -> Iterable:
    yield node
    for ch in node.children:
        yield from _walk(ch)


# ---------------------------------------------------------------- 节点工具

def node_text(node, text_bytes: bytes) -> str:
    return text_bytes[node.start_byte:node.end_byte].decode("utf-8", "replace")


def attr_chain(node) -> Optional[list[str]]:
    """把 a.b.c 形式的 attribute 节点拆成 ['a','b','c']，否则 None。"""
    parts: list[str] = []
    cur = node
    while cur is not None and cur.type == "attribute":
        attr = cur.child_by_field_name("attribute")
        if attr is None:
            return None
        parts.append(attr.text.decode())
        cur = cur.child_by_field_name("object")
    if cur is not None and cur.type == "identifier":
        parts.append(cur.text.decode())
        parts.reverse()
        return parts
    return None


def call_name(node) -> Optional[list[str]]:
    """调用的函数名点链：os.path.join -> ['os','path','join']；非名字调用返回 None。"""
    if node.type != "call":
        return None
    fn = node.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type == "identifier":
        return [fn.text.decode()]
    if fn.type == "attribute":
        return attr_chain(fn)
    return None


def call_args(node) -> list:
    """实参节点列表（去掉 keyword_argument 包装，取其 value）。"""
    al = node.child_by_field_name("arguments")
    if al is None:
        return []
    args = []
    for ch in al.children:
        if ch.type in ("(", ")", ","):
            continue
        if ch.type == "keyword_argument":
            args.append(ch.child_by_field_name("value"))
        else:
            args.append(ch)
    return [a for a in args if a is not None]


def call_kwargs(node) -> dict[str, object]:
    al = node.child_by_field_name("arguments")
    out: dict[str, object] = {}
    if al is None:
        return out
    for ch in al.children:
        if ch.type == "keyword_argument":
            name = ch.child_by_field_name("name")
            val = ch.child_by_field_name("value")
            if name is not None and val is not None:
                out[name.text.decode()] = val
    return out


def start_line(node) -> int:
    return node.start_point[0] + 1


def first_named_child(node) -> Optional[object]:
    """第一个命名子节点：用于字段名在不同 grammar 版本间不稳定的场景
    （如 return_statement 的返回值、raise 的异常对象）。"""
    for ch in node.named_children:
        return ch
    return None


def child(node, field: str, index: Optional[int] = None):
    """字段优先、命名子节点序号回退的统一取值。"""
    v = node.child_by_field_name(field)
    if v is not None:
        return v
    nc = node.named_children
    if index is not None and 0 <= index < len(nc):
        return nc[index]
    return None
