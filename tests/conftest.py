"""pytest 共享 fixture：在临时目录构造微型 Python 仓库。"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from taint import parser_util as pu  # noqa: E402
from taint.engine import Engine, instantiate_findings, run_fixpoint  # noqa: E402
from taint.model import RepoIndex  # noqa: E402


def analyze_sources(files: dict[str, str]):
    """files: {相对路径: 源码} -> (findings, index)。"""
    index = RepoIndex()
    for rel, src in files.items():
        parsed = pu.parse_file(rel, src.encode("utf-8"))
        index.add_file(parsed)
    run_fixpoint(index, logger=lambda *a: None)
    return instantiate_findings(index), index


def kinds_at(findings, file_suffix: str, line: int):
    return {
        f.kind for f in findings
        if f.file.endswith(file_suffix) and f.line == line
    }


@pytest.fixture
def make_repo(tmp_path):
    def _make(files: dict[str, str]):
        for rel, src in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(src, encoding="utf-8")
        return str(tmp_path)
    return _make
