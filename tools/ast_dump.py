"""Dump tree-sitter AST node types (scratch exploration tool)."""
import sys
from tree_sitter_language_pack import get_parser


def dump(node, src, depth=0):
    text = src[node.start_byte:node.end_byte].decode("utf-8", "replace")
    one = text.replace("\n", "\\n")
    if len(one) > 60:
        one = one[:57] + "..."
    print("  " * depth + f"{node.type} [{node.start_point[0]+1}:{node.start_point[1]}] {one!r}")
    for ch in node.children:
        dump(ch, src, depth + 1)


src = open(sys.argv[1], "rb").read() if len(sys.argv) > 1 else b"""
def f(x):
    if not x.isalnum():
        raise ValueError("bad")
    y = "a" + x
    z = [x, "lit"]
    d = {"k": x}
    q = d["k"]
    sql = "s %s" % x
    cursor.execute(sql, (x,))
    subprocess.run(cmd, shell=True)
    requests.get(url, timeout=5)
    with open(p) as fh:
        return fh.read()
    return f(x)
"""
tree = get_parser("python").parse(src)
dump(tree.root_node, src)
