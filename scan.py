"""静态扫描（基线：只有正则匹配，没有数据流分析）。

现在能做的：
  - 逐文件扫关键字（execute / subprocess / requests.get / open），把命中行报出来；
  - 输出 out/report.json。

现在做不到（正是要补的）：
  - 没有污点源（source）概念，参数是不是用户输入完全不看；
  - 没有跨函数/跨文件传播；
  - 没有 sanitizer 白名单，安全实现同样会被报（误报高）；
  - 输出不是 SARIF，不能被 CI 消费；
  - 没有增量扫描。

    python scan.py --repo target --out out/report.json
"""

import argparse
import json
import os
import re

PATTERNS = {
    "sqli": re.compile(r"execute\(.*%"),
    "cmdi": re.compile(r"subprocess\.run\(.*shell=True"),
    "ssrf": re.compile(r"requests\.get\("),
    "path": re.compile(r"open\("),
}


def scan_file(path):
    findings = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            for sink, pat in PATTERNS.items():
                if pat.search(line):
                    findings.append({
                        "file": path,
                        "line": lineno,
                        "sink": sink,
                        "evidence": line.strip()[:200],
                    })
                    break
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="target")
    ap.add_argument("--out", default="out/report.json")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    all_findings = []
    files = 0
    for root, _, names in os.walk(args.repo):
        for n in names:
            if n.endswith(".py"):
                files += 1
                all_findings.extend(scan_file(os.path.join(root, n)))

    report = {
        "tool": "naive-regex-scan",
        "scanned_files": files,
        "finding_count": len(all_findings),
        "findings": all_findings,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(f"scanned {files} files, {len(all_findings)} findings -> {args.out}")


if __name__ == "__main__":
    main()
