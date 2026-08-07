"""Dogfood: Portcullis's own workflows must pass Portcullis."""

from __future__ import annotations

import shutil
from pathlib import Path

from portcullis.core.engine import scan
from portcullis.core.models import ScanConfig

REPO_ROOT = Path(__file__).parent.parent


def test_own_workflows_pass_own_scan(tmp_path):
    shutil.copytree(REPO_ROOT / ".github", tmp_path / ".github")
    report = scan(tmp_path, ScanConfig(), now="2026-01-01T00:00:00+00:00")
    assert report.files_scanned, "expected our own workflow files to be discovered"
    offending = [f for f in report.findings]
    assert offending == [], [(f.rule_id, f.kind, f.file_path, f.line, f.message) for f in offending]
    assert report.score == 100
