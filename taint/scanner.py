"""仓库扫描编排：文件发现、解析缓存、增量分析、SARIF/JSON 报告、CI 基线。"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import time
from typing import Optional

from . import parser_util as pu
from . import rules
from .engine import Finding, instantiate_findings, run_fixpoint
from .model import FuncSummary, RepoIndex

CACHE_VERSION = 3
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "taint-analyzer"


# ============================================================ 文件发现与缓存

def discover_python_files(repo: str) -> list[str]:
    out = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".venv", "venv", "node_modules")]
        for n in names:
            if n.endswith(".py"):
                ab = os.path.join(root, n)
                rel = os.path.relpath(ab, repo).replace("\\", "/")
                out.append(rel)
    out.sort()
    return out


def file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_cache(cache_path: str) -> dict:
    if not os.path.exists(cache_path):
        return {"version": CACHE_VERSION, "files": {}}
    try:
        with open(cache_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {"version": CACHE_VERSION, "files": {}}
    if data.get("version") != CACHE_VERSION:
        return {"version": CACHE_VERSION, "files": {}}
    return data


def save_cache(cache_path: str, cache: dict) -> None:
    os.makedirs(os.path.dirname(cache_path) or ".", exist_ok=True)
    tmp = cache_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=False)
    os.replace(tmp, cache_path)


# ============================================================ 扫描

@dataclasses.dataclass
class ScanResult:
    findings: list[Finding]
    files_scanned: int
    files_total: int
    changed_files: list[str]
    parse_ms: int
    fixpoint_ms: int
    emit_ms: int
    fixpoint_stats: dict
    incremental: bool
    parse_errors: list[str]


def scan_repo(repo: str, cache_path: Optional[str] = None,
              logger=print) -> ScanResult:
    t0 = time.perf_counter()
    cache = load_cache(cache_path) if cache_path else {"version": CACHE_VERSION, "files": {}}
    cached_files: dict = cache["files"]

    rels = discover_python_files(repo)
    index = RepoIndex()
    changed: list[str] = []
    parse_errors: list[str] = []
    reused = 0
    # 缓存恢复的函数：直接装载旧摘要，不参与本轮 fixpoint
    preloaded: set[pu.NodeId] = set()

    for rel in rels:
        ab = os.path.join(repo, rel.replace("/", os.sep))
        with open(ab, "rb") as fh:
            data = fh.read()
        h = file_hash(data)
        entry = cached_files.get(rel)
        if entry is not None and entry.get("hash") == h:
            # 缓存命中：轻量恢复函数表 + 直接装载旧摘要，不重新解析 AST
            parsed = pu.quick_structure(rel, data, entry.get("func_params", {}))
            index.add_file(parsed)
            for sd in entry["summaries"]:
                s = FuncSummary.from_cache(sd)
                index.summaries[s.node_id] = s
                preloaded.add(s.node_id)
            reused += 1
            continue
        changed.append(rel)
        parsed = pu.parse_file(rel, data)
        if parsed.has_error:
            parse_errors.append(rel)
        index.add_file(parsed)

    incremental = reused > 0 and bool(changed)

    # 被删除文件：缓存里有、磁盘上没有（缓存回写时自然丢弃）
    t1 = time.perf_counter()
    stats = run_fixpoint(index, logger=logger, skip_ids=preloaded)
    t2 = time.perf_counter()
    findings = instantiate_findings(index)
    t3 = time.perf_counter()

    # 回写缓存
    if cache_path:
        new_files = {}
        for rel in rels:
            parsed = index.files[rel]
            new_files[rel] = {
                "hash": file_hash(parsed.text_bytes),
                "func_params": {
                    fn.qualname: list(fn.params) for fn in parsed.funcs
                },
                "summaries": [
                    index.summaries[fn.node_id].to_cache() for fn in parsed.funcs
                ],
            }
        save_cache(cache_path, {"version": CACHE_VERSION, "files": new_files})

    return ScanResult(
        findings=findings,
        files_scanned=len(rels),
        files_total=len(rels),
        changed_files=changed,
        parse_ms=int((t1 - t0) * 1000),
        fixpoint_ms=int((t2 - t1) * 1000),
        emit_ms=int((t3 - t2) * 1000),
        fixpoint_stats=stats,
        incremental=incremental,
        parse_errors=parse_errors,
    )


# ============================================================ 报告

def findings_to_dicts(findings: list[Finding]) -> list[dict]:
    return [f.to_dict() for f in findings]


def write_json_report(result: ScanResult, out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    report = {
        "tool": TOOL_NAME,
        "scanned_files": result.files_scanned,
        "finding_count": len(result.findings),
        "incremental": result.incremental,
        "timing_ms": {
            "parse": result.parse_ms,
            "fixpoint": result.fixpoint_ms,
            "emit": result.emit_ms,
            "total": result.parse_ms + result.fixpoint_ms + result.emit_ms,
        },
        "fixpoint": result.fixpoint_stats,
        "parse_errors": result.parse_errors,
        "findings": findings_to_dicts(result.findings),
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)


def to_sarif(result: ScanResult, repo_root: str) -> dict:
    """手写 SARIF 2.1.0（schema 见 SARIF_SCHEMA），CI 可直接消费。"""
    sarif_rules = []
    for kind in rules.SINK_KINDS:
        sarif_rules.append({
            "id": kind,
            "name": f"{kind}-taint",
            "shortDescription": {"text": rules.SINK_MESSAGE[kind].split("：")[0]},
            "fullDescription": {"text": rules.SINK_MESSAGE[kind]},
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://owasp.org/www-community/attacks/",
        })

    sarif_results = []
    for f in result.findings:
        sarif_results.append({
            "ruleId": f.kind,
            "level": "error",
            "message": {
                "text": f"{rules.SINK_MESSAGE[f.kind]}（函数 {f.func}；传播链 {' -> '.join(f.trace)}）"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": f.line,
                        "endLine": max(f.end_line, f.line),
                    },
                }
            }],
            "partialFingerprints": {
                "taintTraceHash": hashlib.sha1(
                    ("|".join(f.trace) + f.kind + str(f.line)).encode()
                ).hexdigest(),
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": __version_str(),
                    "informationUri": "https://example.invalid/taint-analyzer",
                    "rules": sarif_rules,
                }
            },
            "automationDetails": {"id": "taint-analyzer/ci"},
            "results": sarif_results,
        }],
    }


def __version_str() -> str:
    from . import __version__
    return __version__


def write_sarif(result: ScanResult, out_path: str, repo_root: str) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(to_sarif(result, repo_root), fh, ensure_ascii=False, indent=2)


# ============================================================ CI 基线阻断

def load_baseline(path: str) -> set[tuple]:
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {tuple(x) for x in data.get("baseline", [])}


def save_baseline(path: str, findings: list[Finding]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    baseline = sorted({(f.file, f.line, f.kind) for f in findings})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"baseline": [list(x) for x in baseline]}, fh, ensure_ascii=False, indent=2)


def new_violations(findings: list[Finding], baseline: set[tuple]) -> list[Finding]:
    return [f for f in findings if (f.file, f.line, f.kind) not in baseline]


# ============================================================ CLI

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="tree-sitter 静态污点分析器")
    ap.add_argument("--repo", default="target")
    ap.add_argument("--out", default="out/report.json", help="JSON 报告路径")
    ap.add_argument("--sarif", default="out/report.sarif", help="SARIF 输出路径；空串表示不输出")
    ap.add_argument("--cache", default="out/.taint-cache.json", help="增量缓存；空串表示全量无缓存")
    ap.add_argument("--baseline", default="", help="既有违规基线（CI 只阻断新增）")
    ap.add_argument("--update-baseline", action="store_true", help="把当前结果写为基线后退出 0")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    logger = (lambda *a, **k: None) if args.quiet else print
    cache_path = args.cache or None
    t0 = time.perf_counter()
    result = scan_repo(args.repo, cache_path=cache_path, logger=logger)
    write_json_report(result, args.out)
    if args.sarif:
        write_sarif(result, args.sarif, args.repo)
    elapsed = time.perf_counter() - t0

    mode = "incremental" if result.incremental else "full"
    print(
        f"[{mode}] files={result.files_scanned} changed={len(result.changed_files)} "
        f"findings={len(result.findings)} "
        f"parse={result.parse_ms}ms fixpoint={result.fixpoint_ms}ms emit={result.emit_ms}ms "
        f"total={elapsed:.2f}s"
    )
    if result.parse_errors:
        print(f"WARNING: {len(result.parse_errors)} 个文件存在语法错误（按尽力模式分析）")

    if args.update_baseline:
        if args.baseline:
            save_baseline(args.baseline, result.findings)
            print(f"baseline updated -> {args.baseline}")
        return 0

    if args.baseline:
        baseline = load_baseline(args.baseline)
        added = new_violations(result.findings, baseline)
        if added:
            print(f"CI 阻断：发现 {len(added)} 条新增违规（基线外）：")
            for f in added[:50]:
                print(f"  {f.file}:{f.line} [{f.kind}] {f.evidence[:80]}")
            return 2
        print(f"CI 通过：无新增违规（基线内 {len(baseline)} 条已豁免）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
