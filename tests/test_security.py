"""Security hardening of Portcullis's own parser and emitters.

Portcullis parses pipeline files from untrusted repositories, so its parser
must not be turned into a denial-of-service, an out-of-tree file read, or a
stored-XSS vector. These tests lock those defenses in place.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from portcullis.core.engine import MAX_FILE_BYTES, scan
from portcullis.core.models import Report, ScanConfig, Severity
from portcullis.core.risk import assess
from portcullis.emitters import emit_html
from portcullis.platforms.base import ParseError
from portcullis.platforms.github_actions import GitHubActionsPlatform
from portcullis.rules import ALL_RULE_MODULES

NOW = "2026-01-01T00:00:00+00:00"
WF = ".github/workflows/wf.yml"


def _write(tmp_path: Path, content: str | bytes, rel: str = WF) -> Path:
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")
    return target


def _alias_bomb(levels: int, fan: int = 10) -> str:
    b = "on: push\npermissions: {contents: read}\n"
    b += f"x0: &a0 [{','.join(['x'] * fan)}]\n"
    for i in range(levels):
        b += f"x{i + 1}: &a{i + 1} [" + ",".join([f"*a{i}"] * fan) + "]\n"
    b += (
        f"jobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      BOOM: *a{levels}\n"
        "    steps:\n      - run: echo hi\n"
    )
    return b


# --- YAML "billion laughs" alias-bomb DoS -------------------------------------

def test_alias_bomb_is_refused_quickly():
    bomb = _alias_bomb(12)  # ~10^13 nodes if expanded
    t0 = time.time()
    with pytest.raises(ParseError, match="billion-laughs|expands beyond"):
        GitHubActionsPlatform().parse(bomb, WF)
    assert time.time() - t0 < 5, "bomb must be refused in bounded time, not expanded"


def test_alias_bomb_in_scan_degrades_to_finding_not_hang(tmp_path):
    _write(tmp_path, _alias_bomb(12))
    t0 = time.time()
    report = scan(tmp_path, ScanConfig(), now=NOW)
    assert time.time() - t0 < 5
    assert [f.rule_id for f in report.findings] == ["R0"]
    assert report.findings[0].base_severity == Severity.LOW  # never crashes the scan


def test_legitimate_shared_anchor_reuse_is_not_blocked(tmp_path):
    # 80 jobs sharing one anchor via merge key: linear alias use, must parse.
    wf = "on: push\npermissions: {contents: read}\n.def: &d\n  runs-on: ubuntu-latest\njobs:\n"
    for i in range(80):
        wf += f"  job{i}:\n    <<: *d\n    steps:\n      - run: echo {i}\n"
    pipeline = GitHubActionsPlatform().parse(wf, WF)
    assert len(pipeline.jobs) == 80


def test_anchors_without_expansion_still_parse():
    wf = (
        "on: push\npermissions: {contents: read}\nx: &s {A: 1}\n"
        "jobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      <<: *s\n"
        "    steps:\n      - run: echo ok\n"
    )
    pipeline = GitHubActionsPlatform().parse(wf, WF)
    assert pipeline.jobs


# --- oversized-file resource exhaustion ---------------------------------------

def test_oversized_file_is_skipped_not_read(tmp_path):
    padding = "\n" + "#" + "x" * MAX_FILE_BYTES  # just over the cap
    _write(tmp_path, "on: push\njobs: {}\n" + padding)
    report = scan(tmp_path, ScanConfig(), now=NOW)
    assert [f.rule_id for f in report.findings] == ["R0"]
    assert any("size limit" in s["reason"] for s in report.skipped)


def test_normal_sized_file_scans(tmp_path):
    _write(tmp_path, "on: push\npermissions: {contents: read}\njobs:\n  a:\n"
                     "    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n")
    report = scan(tmp_path, ScanConfig(), now=NOW)
    assert all(f.rule_id != "R0" for f in report.findings)


# --- symlink traversal (out-of-tree file read) --------------------------------

def test_symlinked_pipeline_file_is_not_followed(tmp_path):
    secret = tmp_path / "outside_secret.txt"
    secret.write_text("TOP-SECRET-abc123-should-never-be-read", encoding="utf-8")
    link_dir = tmp_path / "repo" / ".github" / "workflows"
    link_dir.mkdir(parents=True)
    link = link_dir / "wf.yml"
    try:
        os.symlink(secret, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted in this environment")
    report = scan(tmp_path / "repo", ScanConfig(), now=NOW)
    # the symlink is skipped, and the secret content never enters the report
    blob = str(report.to_dict())
    assert "TOP-SECRET" not in blob
    assert any("symlink" in s["reason"] for s in report.skipped)


# --- deeply nested input degrades gracefully ----------------------------------

def test_deeply_nested_yaml_does_not_crash(tmp_path):
    depth = 3000
    _write(tmp_path, "a: " + "[" * depth + "]" * depth)
    report = scan(tmp_path, ScanConfig(), now=NOW)  # must not raise
    assert [f.rule_id for f in report.findings] == ["R0"]


# --- stored XSS in the HTML report --------------------------------------------

def _report_from(wf: str) -> Report:
    pipeline = GitHubActionsPlatform().parse(wf, WF)
    findings = []
    for module in ALL_RULE_MODULES:
        findings += module.check(pipeline, ScanConfig())
    assess(findings)
    return Report(
        tool="portcullis", version="0.1.0", target="t", generated_at="x",
        platforms=["github"], files_scanned=[WF], skipped=[], findings=findings,
        score=0, score_formula="f", priority_counts={"P0": 0, "P1": 0, "P2": 0, "P3": 0},
    )


def test_html_report_escapes_injected_markup():
    # A malicious PR-title interpolation carrying markup lands in finding evidence.
    wf = (
        "on: pull_request_target\npermissions: write-all\n"
        "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo \"<script>alert(1)</script><img src=x onerror=alert(2)>"
        "${{ github.event.pull_request.title }}\"\n"
    )
    html = emit_html(_report_from(wf))
    # No raw executable markup survives — the tags are escaped to text.
    assert "<script>alert" not in html
    assert "<img src=x onerror" not in html
    assert "&lt;script&gt;" in html


def test_html_report_has_restrictive_csp():
    wf = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n"
          "    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n")
    html = emit_html(_report_from(wf))
    assert "Content-Security-Policy" in html
    assert "default-src 'none'" in html
    assert "script-src" not in html.split("</head>")[0].replace("default-src", "")
