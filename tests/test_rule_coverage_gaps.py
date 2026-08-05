"""Regression tests for rule behaviors that were implemented but previously
untested (found via a coverage gap analysis): R2 script-injection, R6
unverified-download, R3 docker:// action refs, and R4 top-level broad-write."""

from __future__ import annotations

from pathlib import Path

from portcullis.core.engine import scan
from portcullis.core.models import Confidence, ScanConfig, Severity

WF = ".github/workflows/wf.yml"
NOW = "2026-01-01T00:00:00+00:00"


def _scan(tmp_path: Path, content: str, rel: str = WF):
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return scan(tmp_path, ScanConfig(), now=NOW)


def kinds(report) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in report.findings:
        out.setdefault(f.kind, []).append(f)
    return out


# --- R2 script-injection (actions/github-script body) --------------------------

def test_github_script_untrusted_interpolation_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: issues
permissions: {contents: read}
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@0000000000000000000000000000000000000001
        with:
          script: |
            const title = "${{ github.event.issue.title }}";
            console.log(title);
""",
    )
    ks = kinds(report)
    assert "script-injection" in ks
    f = ks["script-injection"][0]
    assert f.rule_id == "R2"
    assert f.base_severity == Severity.HIGH
    # 'issues' is a privileged untrusted trigger → escalates to CRITICAL
    assert f.severity == Severity.CRITICAL and f.escalated


def test_github_script_trusted_context_not_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@0000000000000000000000000000000000000001
        with:
          script: console.log("${{ github.sha }}");
""",
    )
    assert "script-injection" not in kinds(report)


# --- R6 unverified-download (download without checksum, no pipe-to-shell) -------

def test_unverified_download_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sSL https://example.com/tool.tar.gz -o tool.tar.gz
""",
    )
    ks = kinds(report)
    assert "unverified-download" in ks
    f = ks["unverified-download"][0]
    assert f.rule_id == "R6"
    assert f.confidence == Confidence.LOW  # low-confidence by design (many are benign)


def test_download_with_checksum_not_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -sSL https://example.com/tool.tar.gz -o tool.tar.gz
          sha256sum -c tool.sha256
""",
    )
    assert "unverified-download" not in kinds(report)


# --- R5 secret-cli-arg (secret on a command line, not an echo) -----------------

def test_secret_on_command_line_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy --token ${{ secrets.FIXTURE_FAKE_TOKEN }}
""",
    )
    ks = kinds(report)
    assert "secret-cli-arg" in ks
    f = ks["secret-cli-arg"][0]
    assert f.rule_id == "R5"
    assert "FIXTURE_FAKE_TOKEN" in f.evidence


# --- R3 docker:// action reference (unpinned) ----------------------------------

def test_docker_uses_without_digest_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://example.com/tool:latest
""",
    )
    ks = kinds(report)
    assert "image-mutable-latest" in ks
    assert any("docker://" in f.evidence for f in ks["image-mutable-latest"])


def test_docker_uses_with_digest_not_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://example.com/tool@sha256:0000000000000000000000000000000000000000000000000000000000000001
""",
    )
    assert all(f.rule_id != "R3" for f in report.findings)


# --- R4 permissions branches (missing block, top-level write-all, job broad-write) ---

def test_missing_permissions_block_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
""",
    )
    assert "missing-permissions" in kinds(report)


def test_top_level_write_all_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
""",
    )
    ks = kinds(report)
    assert "write-all" in ks
    assert ks["write-all"][0].job_name is None  # workflow-level


def test_job_level_write_all_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo ok
""",
    )
    ks = kinds(report)
    assert "write-all" in ks
    assert ks["write-all"][0].job_name == "a"


def test_job_level_broad_write_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      packages: write
      id-token: write
    steps:
      - run: echo ok
""",
    )
    ks = kinds(report)
    assert "broad-write" in ks
    assert ks["broad-write"][0].job_name == "a"


# --- R4 top-level broad-write (>=3 write scopes at workflow level) --------------

def test_top_level_broad_write_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions:
  contents: write
  packages: write
  issues: write
  pull-requests: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
""",
    )
    ks = kinds(report)
    assert "broad-write" in ks
    bw = ks["broad-write"][0]
    assert bw.rule_id == "R4"
    assert bw.job_name is None  # workflow-level, not a specific job
    assert bw.key_path == "permissions"
