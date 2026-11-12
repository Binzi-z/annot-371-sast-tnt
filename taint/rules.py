"""污点规则：source / sink / sanitizer / 验证守卫。

规则全部基于 tree-sitter AST 结构手工定义（不使用 Semgrep/CodeQL 规则）。
sink 只描述"危险 API 形态"；是否真正成洞由引擎的数据流 + sanitizer 判定。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import parser_util as pu

# ----------------------------------------------------------------- 污点源

# 显式 Web 源：Flask / Django 风格的请求输入访问
SOURCE_CHAINS = (
    ("request", "args"),
    ("request", "form"),
    ("request", "json"),
    ("request", "values"),
    ("request", "cookies"),
    ("request", "headers"),
    ("request", "data"),
    ("request", "files"),
    ("request", "GET"),
    ("request", "POST"),
    ("flask", "request"),
)
SOURCE_FUNC_CHAINS = (
    ("sys", "argv"),
    ("os", "environ"),
    ("os", "getenv"),
)


def explicit_source(node) -> bool:
    """该表达式是否为显式不可信输入源。"""
    if node.type == "attribute":
        chain = pu.attr_chain(node)
        if chain and tuple(chain[:2]) in SOURCE_CHAINS:
            return True
        if chain and tuple(chain) in SOURCE_FUNC_CHAINS:
            return True
    if node.type == "subscript":
        obj = node.child_by_field_name("object")
        if obj is not None and explicit_source(obj):
            return True
    if node.type == "call":
        chain = pu.call_name(node)
        if chain and tuple(chain) in SOURCE_FUNC_CHAINS:
            return True
        # request.args.get("x") / request.json["..."]
        func = node.child_by_field_name("function")
        if func is not None and explicit_source(func):
            return True
    return False


# 隐式源策略：服务层仓库里 handler 函数参数即外部输入边界。
# 引擎在分析时假设所有形参带污点，最终实例化阶段再用跨函数可达性确认，
# 避免无脑全报（见 engine.instantiate_findings）。

# ----------------------------------------------------------------- sink 定义

SINK_KINDS = ("sqli", "cmdi", "ssrf", "path")
SINK_MESSAGE = {
    "sqli": "SQL 注入：污点进入动态 SQL 执行且未使用参数化查询",
    "cmdi": "命令注入：污点进入 shell 命令执行",
    "ssrf": "SSRF：污点进入外部 URL 请求且未通过主机白名单校验",
    "path": "路径穿越：污点进入文件路径且未通过 realpath 前缀校验",
}


@dataclass
class SinkHit:
    kind: str
    node: object          # 触发 sink 的 call 节点
    arg_index: int        # 被检查的实参下标
    arg_node: object


def match_sink(node) -> Optional[SinkHit]:
    """若节点是四类危险 API 之一，返回 SinkHit（含应做污点检查的实参）。"""
    if node.type != "call":
        return None
    chain = pu.call_name(node)
    if not chain:
        return None
    name = chain[-1]
    args = pu.call_args(node)
    kwargs = pu.call_kwargs(node)

    # ---- SQL：cursor.execute / executemany，且为动态拼接 SQL ----
    if name in ("execute", "executemany") and len(chain) >= 2:
        if not args:
            return None
        sql_arg = args[0]
        if _is_static_string(sql_arg):
            return None  # 静态 SQL 语句本身无注入面
        # 参数化 execute(sql, params)：SQL 文本不脏时安全
        if len(args) >= 2 and not _expr_trivially_tainted(sql_arg):
            return None
        return SinkHit("sqli", node, 0, sql_arg)

    # ---- 命令注入：subprocess.* / os.system / os.popen ----
    if (tuple(chain[:2]) == ("subprocess", "run")
            or (chain[0] == "subprocess" and name in (
                "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"))
            or (chain[:1] == ["os"] and name in ("system", "popen"))):
        shell_true = _kw_truthy(kwargs.get("shell"))
        if name in ("system", "popen", "getoutput", "getstatusoutput"):
            # os.system / getoutput 天然走 shell
            if args:
                return SinkHit("cmdi", node, 0, args[0])
            return None
        if shell_true and args:
            return SinkHit("cmdi", node, 0, args[0])
        if not shell_true and args and args[0].type not in ("list", "tuple"):
            # 非 list 形式且没显式 shell=False：字符串命令仍有注入面（保守）
            return SinkHit("cmdi", node, 0, args[0])
        return None

    # ---- SSRF：requests / httpx / urllib 的 URL 请求 ----
    if _is_http_request(chain):
        url_arg = kwargs.get("url") or (args[0] if args else None)
        if url_arg is not None:
            return SinkHit("ssrf", node, 0, url_arg)
        return None

    # ---- 路径穿越：open / 文件 IO ----
    if _is_file_open(chain):
        p_arg = kwargs.get("file") or kwargs.get("path") or (args[0] if args else None)
        if p_arg is not None:
            return SinkHit("path", node, 0, p_arg)
        return None
    return None


def _is_http_request(chain) -> bool:
    if chain[0] in ("requests", "httpx") and chain[-1] in (
        "get", "post", "put", "delete", "patch", "head", "request", "stream", "Client",
    ):
        return True
    if len(chain) >= 3 and chain[:2] == ("urllib", "request") and chain[-1] == "urlopen":
        return True
    if tuple(chain) == ("urlopen",):
        return True
    return False


def _is_file_open(chain) -> bool:
    if tuple(chain) == ("open",):
        return True
    if chain[0] in ("os",) and chain[-1] in ("open", "remove", "unlink", "rmdir", "mkdir", "stat", "chmod"):
        return True
    if chain[0] in ("shutil",) and chain[-1] in ("copy", "copyfile", "move", "rmtree"):
        return True
    if chain[0] in ("pathlib", "Path"):
        return False  # Path(...) 构造本身不触达文件系统，交给 open() 调用
    if len(chain) >= 2 and chain[0] == "Path" and chain[-1] in (
        "open", "read_text", "write_text", "read_bytes", "unlink", "glob",
    ):
        return True
    return False


def _kw_truthy(node) -> bool:
    if node is None:
        return False
    return node.type == "true"


def _is_static_string(node) -> bool:
    # 普通字符串字面量才算静态；f-string 含插值，不是静态 SQL
    return node.type == "string" and not any(
        ch.type == "interpolation" for ch in node.children
    )


def _expr_trivially_tainted(node) -> bool:
    """仅用于 sink 形态判断的粗筛：SQL 文本里是否出现 % 格式化 / f-string / 拼接。"""
    if node.type == "binary_operator":
        op = node.child_by_field_name("operator")
        if op is not None and op.text == b"%":
            return True
        return _expr_trivially_tainted(pu.child(node, "left", 0)) or \
            _expr_trivially_tainted(pu.child(node, "right", 1))
    if node.type == "string":
        # f-string：含 interpolation 子节点
        return any(ch.type == "interpolation" for ch in node.children)
    if node.type == "call":
        chain = pu.call_name(node)
        if chain and chain[-1] == "format":
            return True
    return False


# ----------------------------------------------------------------- sanitizer

# 命名白名单：命中即视为对实参做了净化（返回干净值）
SANITIZER_FUNCS = {
    # 通用转义 / 编码
    "escape", "html_escape", "quote", "quote_plus", "urlencode",
    "sanitize", "sanitize_input", "sanitize_filename", "clean", "purify",
    # SQL
    "mogrify",
    # 路径
    "safe_join", "secure_filename",
    # 命令参数
    "shlex_quote", "quote_cmd",
    # 校验型（返回 bool 的由守卫处理，这里处理抛异常/返回干净值的封装）
    "validate_input", "validate_url", "validate_name", "ensure_allowed",
}
SANITIZER_CHAINS = (
    ("shlex", "quote"),
    ("urllib", "parse", "quote"),
    ("urllib", "parse", "quote_plus"),
    ("html", "escape"),
    ("flask", "escape"),
    ("werkzeug", "utils", "secure_filename"),
    ("werkzeug", "secure_filename"),
)

# 净化型内置/库调用：输出不再带污点
NEUTRALIZING_CHAINS = (
    ("os", "path", "realpath"),
    ("os", "realpath"),
    ("os", "path", "abspath"),
    ("os", "abspath"),
)


def is_sanitizer_call(node) -> bool:
    chain = pu.call_name(node)
    if not chain:
        return False
    if tuple(chain) in SANITIZER_CHAINS or tuple(chain) in NEUTRALIZING_CHAINS:
        return True
    return chain[-1] in SANITIZER_FUNCS


# ----------------------------------------------------------------- 验证守卫

# 被允许的校验方法（出现在 if 条件里即建立守卫）
GUARD_METHODS = {
    "isalnum", "isalpha", "isdigit", "isdecimal", "isnumeric", "isascii",
    "isidentifier",
}
GUARD_FUNCS = {
    "isalnum", "isalpha", "isdigit",
    "re_match", "re_fullmatch", "fullmatch", "match",
    "is_valid_host", "allowed_host", "is_allowed",
}
# 白名单包含判断
GUARD_CONTAINER_METHODS = {"startswith", "endswith"}


@dataclass
class Guard:
    """一条已建立的守卫：被保护的根变量名 + 守卫类型。"""

    roots: frozenset[str]
    kind: str           # allowlist / host-prefix / path-prefix
    guard_node: object


def extract_guard(if_node, text_bytes: bytes) -> Optional[Guard]:
    """分析 if 条件，识别"校验失败即拒绝"的净化守卫。

    调用方需保证 if 体内含 raise/return/continue/break（终止型分支）。
    """
    cond = if_node.child_by_field_name("condition")
    if cond is None:
        return None

    # 路径守卫：path.startswith(realpath(base)+sep) —— 直接按结构识别
    g = _path_prefix_guard(cond, text_bytes)
    if g is not None:
        return g

    # 主机白名单：url.startswith("https://allowed/") / host in ALLOWED
    g = _host_guard(cond)
    if g is not None:
        return g

    # 布尔校验：if not x.isalnum(): reject  /  if re.fullmatch(...): ok 形式由调用方区分
    g = _bool_guard(cond)
    if g is not None:
        return g
    return None


def _terminating(block) -> bool:
    """块是否以终止语句结束（raise/return/raise ...）。"""
    if block is None:
        return False
    for st in block.children:
        if st.type in ("raise_statement", "return_statement", "continue_statement", "break_statement"):
            return True
    return False


def _roots_of(node) -> frozenset[str]:
    roots: set[str] = set()
    for sub in _walk(node):
        if sub.type == "identifier":
            roots.add(sub.text.decode())
            break  # 表达式最左标识符即根
    return frozenset(roots)


def _walk(node):
    yield node
    for ch in node.children:
        yield from _walk(ch)


def _bool_guard(cond) -> Optional[Guard]:
    # not x.isalnum()  /  not is_valid(x)
    target = cond
    negated = False
    if cond.type == "not_operator":
        target = cond.child_by_field_name("argument")
        negated = True
    if target is None:
        return None
    if target.type == "call":
        chain = pu.call_name(target)
        if not chain:
            return None
        if chain[-1] in GUARD_METHODS or chain[-1] in GUARD_FUNCS:
            roots = set()
            for a in pu.call_args(target):
                roots |= set(_roots_of(a))
            obj = target.child_by_field_name("function")
            if obj is not None and obj.type == "attribute":
                roots |= set(_roots_of(obj.child_by_field_name("object")))
            if roots:
                return Guard(frozenset(roots), "allowlist", cond)
    # x in ALLOWED_HOSTS（容器白名单）
    if target.type == "comparison_operator":
        if _is_in_check(target):
            roots = _roots_of(target.child_by_field_name("left"))
            return Guard(roots, "allowlist", cond)
    return None


def _is_in_check(cmp_node) -> bool:
    for ch in cmp_node.children:
        if ch.type == "in" or (ch.type == "not" and any(c.type == "in" for c in cmp_node.children)):
            return True
    return False


def _host_guard(cond) -> Optional[Guard]:
    target = cond
    negated = False
    if cond.type == "not_operator":
        target = cond.child_by_field_name("argument")
        negated = True
    if target is None:
        return None
    if target.type == "call":
        chain = pu.call_name(target)
        if chain and chain[-1] in GUARD_CONTAINER_METHODS:
            # url.startswith("https://...")
            roots = _roots_of(target.child_by_field_name("function").child_by_field_name("object"))
            return Guard(roots, "host-prefix", cond)
    if target.type == "comparison_operator" and _is_in_check(target):
        roots = _roots_of(target.child_by_field_name("left"))
        return Guard(roots, "host-prefix", cond)
    return None


def _path_prefix_guard(cond, text_bytes) -> Optional[Guard]:
    """识别 path.startswith(...) 形式；参数里出现 realpath/abspath 才算路径守卫。"""
    target = cond
    if cond.type == "not_operator":
        target = cond.child_by_field_name("argument")
    if target is None or target.type != "call":
        return None
    chain = pu.call_name(target)
    if not chain or chain[-1] != "startswith":
        return None
    func = target.child_by_field_name("function")
    roots = _roots_of(func.child_by_field_name("object"))
    arg_src = pu.node_text(target, text_bytes)
    if "realpath" in arg_src or "abspath" in arg_src:
        return Guard(roots, "path-prefix", cond)
    return None
