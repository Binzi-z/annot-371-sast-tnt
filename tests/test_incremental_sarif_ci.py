"""增量缓存、SARIF 结构、CI 基线阻断测试。"""
import json
import os

from taint.scanner import (
    load_baseline,
    new_violations,
    save_baseline,
    scan_repo,
    to_sarif,
    write_sarif,
)


VULN = '''
import subprocess


def f(x):
    return subprocess.run("ping " + x, shell=True)
'''

SAFE = '''
import subprocess


def f(x):
    if not x.isalnum():
        raise ValueError()
    return subprocess.run(["ping", x])
'''


def _write(repo, name, content):
    with open(os.path.join(repo, name), "w", encoding="utf-8") as fh:
        fh.write(content)


def test_incremental_cache_reuses_summaries(make_repo):
    repo = make_repo({"svc.py": VULN})
    cache = os.path.join(repo, ".cache.json")
    r1 = scan_repo(repo, cache_path=cache, logger=lambda *a: None)
    assert len(r1.findings) == 1
    assert r1.fixpoint_stats["skipped"] == 0

    # 第二次：零变更，全部命中缓存
    r2 = scan_repo(repo, cache_path=cache, logger=lambda *a: None)
    assert len(r2.findings) == 1
    assert r2.changed_files == []
    assert r2.fixpoint_stats["skipped"] == r2.files_total
    assert r2.fixpoint_stats["total_analyzes"] == 0


def test_incremental_only_reparses_changed(make_repo):
    repo = make_repo({"a.py": VULN, "b.py": SAFE})
    cache = os.path.join(repo, ".cache.json")
    scan_repo(repo, cache_path=cache, logger=lambda *a: None)

    _write(repo, "b.py", SAFE + "\n# changed comment\n")
    r = scan_repo(repo, cache_path=cache, logger=lambda *a: None)
    assert r.changed_files == ["b.py"]
    assert r.incremental is True
    # a.py 被跳过，只分析 b.py 的函数
    assert r.fixpoint_stats["skipped"] >= 1


def test_sarif_structure(make_repo):
    repo = make_repo({"svc.py": VULN})
    r = scan_repo(repo, cache_path=None, logger=lambda *a: None)
    sarif = to_sarif(r, repo)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert {"sqli", "cmdi", "ssrf", "path"} <= rule_ids
    res = run["results"]
    assert len(res) == 1
    assert res[0]["ruleId"] == "cmdi"
    loc = res[0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"].endswith("svc.py")
    assert loc["region"]["startLine"] >= 1


def test_sarif_file_roundtrip(make_repo):
    repo = make_repo({"svc.py": VULN})
    r = scan_repo(repo, cache_path=None, logger=lambda *a: None)
    out = os.path.join(repo, "r.sarif")
    write_sarif(r, out, repo)
    data = json.load(open(out, encoding="utf-8"))
    assert data["runs"][0]["results"][0]["level"] == "error"


def test_ci_baseline_blocks_only_new(make_repo):
    repo = make_repo({"svc.py": VULN})
    r1 = scan_repo(repo, cache_path=None, logger=lambda *a: None)
    baseline_path = os.path.join(repo, "baseline.json")
    save_baseline(baseline_path, r1.findings)
    baseline = load_baseline(baseline_path)

    # 同样的结果：基线内，无新增
    assert new_violations(r1.findings, baseline) == []

    # 新增一条违规
    _write(repo, "svc2.py", VULN)
    r2 = scan_repo(repo, cache_path=None, logger=lambda *a: None)
    added = new_violations(r2.findings, baseline)
    assert len(added) == 1
    assert added[0].file.endswith("svc2.py")
