"""四类 sink 的检测与 sanitizer 抑制（直接对齐 50 条标注样本的代码形态）。"""
from conftest import analyze_sources, kinds_at


VULN_AND_SAFE = {
    "svc.py": '''import os
import subprocess
import requests


def vuln_sqli(cursor, user_input):
    sql = "SELECT * FROM t WHERE name LIKE '%%%s%%'" % user_input
    cursor.execute(sql)
    return cursor.fetchall()


def safe_sqli(cursor, user_input):
    sql = "SELECT * FROM t WHERE name LIKE %s"
    cursor.execute(sql, (user_input,))
    return cursor.fetchall()


def vuln_cmdi(user_arg):
    cmd = "ping -c 1 " + user_arg
    return subprocess.run(cmd, shell=True, capture_output=True)


def safe_cmdi(user_arg):
    if not user_arg.isalnum():
        raise ValueError("bad arg")
    return subprocess.run(["ping", "-c", "1", user_arg], capture_output=True)


def vuln_ssrf(url):
    return requests.get(url, timeout=5).text


def safe_ssrf(url):
    if not url.startswith("https://api.example.com/"):
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5).text


def vuln_path(name):
    path = os.path.join("/srv/data", name)
    with open(path) as f:
        return f.read()


def safe_path(name):
    base = "/srv/data"
    path = os.path.realpath(os.path.join(base, name))
    if not path.startswith(os.path.realpath(base) + os.sep):
        raise ValueError("traversal")
    with open(path) as f:
        return f.read()
'''
}


def test_four_vuln_sinks_detected():
    findings, _ = analyze_sources(VULN_AND_SAFE)
    assert kinds_at(findings, "svc.py", 8) == {"sqli"}
    assert kinds_at(findings, "svc.py", 20) == {"cmdi"}
    assert kinds_at(findings, "svc.py", 30) == {"ssrf"}
    assert kinds_at(findings, "svc.py", 41) == {"path"}


def test_four_safe_implementations_suppressed():
    findings, _ = analyze_sources(VULN_AND_SAFE)
    # 安全实现所在行不应有任何发现
    safe_lines = {14, 26, 36, 50}
    assert all(f.line not in safe_lines for f in findings)
    assert len(findings) == 4


def test_static_sql_not_flagged():
    findings, _ = analyze_sources({"a.py": '''
def f(cursor):
    cursor.execute("SELECT 1")
'''})
    assert findings == []


def test_shell_false_list_not_flagged():
    findings, _ = analyze_sources({"a.py": '''
import subprocess
def f(x):
    return subprocess.run(["ls", x], capture_output=True)
'''})
    assert findings == []


def test_fstring_sql_detected():
    findings, _ = analyze_sources({"a.py": '''
def f(cursor, name):
    cursor.execute(f"SELECT * FROM t WHERE n='{name}'")
'''})
    assert len(findings) == 1 and findings[0].kind == "sqli"


def test_os_system_detected():
    findings, _ = analyze_sources({"a.py": '''
import os
def f(x):
    os.system("ping " + x)
'''})
    assert len(findings) == 1 and findings[0].kind == "cmdi"


def test_shlex_quote_sanitizer():
    findings, _ = analyze_sources({"a.py": '''
import subprocess
import shlex
def f(x):
    return subprocess.run("echo " + shlex.quote(x), shell=True)
'''})
    assert findings == []


def test_secure_filename_sanitizer():
    findings, _ = analyze_sources({"a.py": '''
from werkzeug.utils import secure_filename
def f(name):
    with open("/u/" + secure_filename(name)) as fh:
        return fh.read()
'''})
    assert findings == []
