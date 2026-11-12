"""跨函数、跨文件、字段/集合/返回值传播测试。"""
from conftest import analyze_sources, kinds_at


def test_cross_file_param_to_sink():
    files = {
        "pkg/db.py": '''
def run_query(cursor, q):
    cursor.execute(q)
    return cursor.fetchall()
''',
        "svc.py": '''
from pkg.db import run_query


def handler(cursor, request):
    user_input = request.args.get("name")
    run_query(cursor, "SELECT * FROM t WHERE n='" + user_input + "'")
''',
    }
    findings, _ = analyze_sources(files)
    # sink 报在定义点 db.py 的 execute 行
    assert any(f.kind == "sqli" and f.file.endswith("db.py") and f.line == 3 for f in findings)


def test_cross_file_return_value_propagation():
    files = {
        "pkg/util.py": '''
def build_url(host):
    return "https://" + host + "/v1"
''',
        "svc.py": '''
from pkg.util import build_url
import requests


def handler(req):
    url = build_url(req.args["host"])
    return requests.get(url)
''',
    }
    findings, _ = analyze_sources(files)
    assert any(f.kind == "ssrf" and f.file.endswith("svc.py") for f in findings)


def test_field_and_list_propagation():
    findings, _ = analyze_sources({
        "a.py": '''
import subprocess


class Req:
    def __init__(self, name):
        self.name = name


def f(req):
    items = [req.name, "static"]
    subprocess.run("echo " + items[0], shell=True)
'''})
    assert len(findings) == 1 and findings[0].kind == "cmdi"


def test_dict_subscript_propagation():
    findings, _ = analyze_sources({
        "a.py": '''
def f(req):
    d = {"k": req.name}
    with open("/tmp/" + d["k"]) as fh:
        return fh.read()
'''})
    assert len(findings) == 1 and findings[0].kind == "path"


def test_interprocedural_chain_three_hops():
    files = {
        "a.py": '''
def leaf(cmd):
    import subprocess
    subprocess.run(cmd, shell=True)


def mid(x):
    return leaf("run " + x)


def entry(user):
    mid(user)
''',
    }
    findings, _ = analyze_sources(files)
    assert len(findings) == 1 and findings[0].kind == "cmdi"
    # 传播链应包含三个函数
    joined = " -> ".join(findings[0].trace)
    assert "entry" in joined and "mid" in joined and "leaf" in joined


def test_wrapper_returns_taint_summary():
    files = {
        "a.py": '''
def identity(x):
    y = x.strip()
    return y


def sink_fn(req):
    import requests
    url = identity(req)
    requests.get(url)
''',
    }
    findings, _ = analyze_sources(files)
    assert any(f.kind == "ssrf" for f in findings)


def test_explicit_flask_source_taints():
    findings, _ = analyze_sources({
        "a.py": '''
import requests


def f():
    url = request.args.get("u")
    requests.get(url)
''',
    })
    assert any(f.kind == "ssrf" for f in findings)


def test_clean_data_flow_no_finding():
    findings, _ = analyze_sources({
        "a.py": '''
import subprocess


def f():
    base = "https://api.example.com/v1"
    import requests
    return requests.get(base)
''',
    })
    assert findings == []
