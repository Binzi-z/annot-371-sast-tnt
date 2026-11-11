"""生成用于污点分析评测的代码仓库与标注样本（本地、确定、可复现）。

产物：
  target/               约 20 万行的 Python 代码（含真实可执行的函数签名）
  samples/labels.json   50 条标注：{file, line, sink, vuln}

注入的漏洞类型：sqli / cmdi / ssrf / path
另外注入等量的"看起来可疑但已做白名单/转义"的等价代码，用 vuln=false 标注，
用来压低误报——只按关键字匹配的实现会在这里翻车。

    python tools/gen_corpus.py --files 800 --out target --labels samples/labels.json
"""

import argparse
import json
import os
import random

SINKS = ["sqli", "cmdi", "ssrf", "path"]

TPL_HEADER = '''"""module {mod}: service layer (generated corpus)."""

import os
import subprocess
import requests


'''

TPL_VULN = {
    "sqli": '''def query_{name}(cursor, user_input):
    sql = "SELECT * FROM {table} WHERE name LIKE '%%%s%%'" % user_input
    cursor.execute(sql)
    return cursor.fetchall()
''',
    "cmdi": '''def run_{name}(user_arg):
    cmd = "ping -c 1 " + user_arg
    return subprocess.run(cmd, shell=True, capture_output=True)
''',
    "ssrf": '''def fetch_{name}(url):
    return requests.get(url, timeout=5).text
''',
    "path": '''def read_{name}(name):
    path = os.path.join("/srv/data", name)
    with open(path) as f:
        return f.read()
''',
}

TPL_SAFE = {
    "sqli": '''def query_{name}_safe(cursor, user_input):
    sql = "SELECT * FROM {table} WHERE name LIKE %s"
    cursor.execute(sql, (user_input,))
    return cursor.fetchall()
''',
    "cmdi": '''def run_{name}_safe(user_arg):
    if not user_arg.isalnum():
        raise ValueError("bad arg")
    return subprocess.run(["ping", "-c", "1", user_arg], capture_output=True)
''',
    "ssrf": '''def fetch_{name}_safe(url):
    if not url.startswith("https://api.example.com/"):
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5).text
''',
    "path": '''def read_{name}_safe(name):
    base = "/srv/data"
    path = os.path.realpath(os.path.join(base, name))
    if not path.startswith(os.path.realpath(base) + os.sep):
        raise ValueError("traversal")
    with open(path) as f:
        return f.read()
''',
}

TPL_FILLER = '''def helper_{name}(payload):
    total = 0
    for item in payload:
        if item.get("active"):
            total += int(item.get("weight", 0))
    return total


def transform_{name}(rows):
    out = []
    for row in rows:
        out.append({{"id": row[0], "name": str(row[1]).strip()}})
    return out


'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=800)
    ap.add_argument("--lines", type=int, default=250, help="target lines per file")
    ap.add_argument("--out", default="target")
    ap.add_argument("--labels", default="samples/labels.json")
    ap.add_argument("--seed", type=int, default=20261111)
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(os.path.dirname(args.labels) or ".", exist_ok=True)

    labels = []
    total_lines = 0

    for f in range(args.files):
        mod = f"svc_{f:04d}"
        body = [TPL_HEADER.format(mod=mod)]
        # 每个文件放 0~1 个漏洞函数，前 50 个命中作为标注样本
        kind = SINKS[f % len(SINKS)]
        has_vuln = (f % 3 != 0)
        table = f"t_{f:04d}"
        fn = f"m{f:04d}"

        if has_vuln:
            code = TPL_VULN[kind].format(name=fn, table=table)
        else:
            code = TPL_SAFE[kind].format(name=fn, table=table)
        body.append(code)
        body.append("\n")
        # 一半文件同时放一份安全实现，制造近似重复对，检验是否只靠关键字
        safe = TPL_SAFE[kind].format(name=f"n{f:04d}", table=table)
        body.append(safe)
        body.append("\n")

        while sum(x.count("\n") for x in body) < args.lines:
            body.append(TPL_FILLER.format(name=f"{f}_{rnd.randint(0, 9999)}"))

        text = "".join(body)
        path = os.path.join(args.out, f"{mod}.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        total_lines += text.count("\n")

        # 记录标注：前 50 条样本里既有漏洞也有安全实现
        if len(labels) < 50:
            lines = text.split("\n")
            target_line = None
            key = "subprocess.run" if kind == "cmdi" else ("requests.get" if kind == "ssrf" else ("open(" if kind == "path" else "execute("))
            for i, ln in enumerate(lines, start=1):
                if key in ln:
                    target_line = i
                    break
            if target_line:
                labels.append({
                    "file": f"{mod}.py",
                    "line": target_line,
                    "sink": kind,
                    "vuln": bool(has_vuln),
                })

    with open(args.labels, "w", encoding="utf-8") as fh:
        json.dump({"sample_count": len(labels), "labels": labels}, fh, ensure_ascii=False, indent=2)

    print(f"generated {args.files} files, {total_lines} lines -> {args.out}")
    print(f"labels: {len(labels)} -> {args.labels}")


if __name__ == "__main__":
    main()
