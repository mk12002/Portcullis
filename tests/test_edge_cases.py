"""Edge cases: empty/malformed/anchors/non-UTF-8/multi-doc/reusable workflows.
Malformed input must degrade to warnings + LOW findings, never crash."""

from __future__ import annotations

from pathlib import Path

from portcullis.core.engine import scan
from portcullis.core.models import ScanConfig
from portcullis.platforms.github_actions import GitHubActionsPlatform


def _scan_tree(tmp_path: Path, rel: str, content: str | bytes):
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")
    return scan(tmp_path, ScanConfig(), now="2026-01-01T00:00:00+00:00")


WF = ".github/workflows/wf.yml"


def test_empty_workflow_is_low_parse_finding(tmp_path):
    report = _scan_tree(tmp_path, WF, "")
    assert [f.rule_id for f in report.findings] == ["R0"]
    assert report.skipped


def test_non_utf8_file_degrades_gracefully(tmp_path):
    report = _scan_tree(tmp_path, WF, b"\xff\xfe\x00bad bytes \x9c")
    assert [f.rule_id for f in report.findings] == ["R0"]


def test_yaml_anchors_and_merge_keys(tmp_path):
    report = _scan_tree(
        tmp_path,
        WF,
        """
name: anchors
on: push
permissions:
  contents: read
x-shared: &shared
  TOOL: pinned
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      <<: *shared
    steps:
      - run: echo ok
""",
    )
    assert all(f.rule_id != "R0" for f in report.findings)


def test_multi_document_yaml_uses_first_doc(tmp_path):
    report = _scan_tree(
        tmp_path,
        WF,
        "name: doc1\non: push\npermissions: {contents: read}\n"
        "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
        "---\nname: doc2\n",
    )
    assert all(f.rule_id != "R0" for f in report.findings)


def test_job_with_no_steps(tmp_path):
    report = _scan_tree(
        tmp_path,
        WF,
        "name: empty-job\non: push\npermissions: {contents: read}\n"
        "jobs:\n  a:\n    runs-on: ubuntu-latest\n",
    )
    assert all(f.rule_id != "R0" for f in report.findings)


def test_remote_reusable_workflow_pinning_flagged(tmp_path):
    report = _scan_tree(
        tmp_path,
        WF,
        "name: reuse\non: push\npermissions: {contents: read}\n"
        "jobs:\n  call:\n    uses: example-org/flows/.github/workflows/build.yml@main\n",
    )
    kinds = {f.kind for f in report.findings}
    assert "unpinned-third-party" in kinds


def test_local_reusable_workflow_not_flagged_for_pinning(tmp_path):
    report = _scan_tree(
        tmp_path,
        WF,
        "name: reuse\non: push\npermissions: {contents: read}\n"
        "jobs:\n  call:\n    uses: ./.github/workflows/build.yml\n",
    )
    assert all(f.rule_id != "R3" for f in report.findings)


def test_on_string_and_list_forms(tmp_path):
    platform = GitHubActionsPlatform()
    p1 = platform.parse("on: push\njobs: {}\n", WF)
    assert [t.event for t in p1.triggers] == ["push"]
    p2 = platform.parse("on: [push, pull_request]\njobs: {}\n", WF)
    assert [t.event for t in p2.triggers] == ["push", "pull_request"]
    assert not p2.triggers[1].untrusted_privileged
    assert p2.triggers[1].untrusted_input


def test_workflow_root_not_mapping_is_parse_finding(tmp_path):
    report = _scan_tree(tmp_path, WF, "- just\n- a\n- list\n")
    assert [f.rule_id for f in report.findings] == ["R0"]


def test_gitignore_respected(tmp_path):
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    wf = "name: x\non: push\njobs: {}\n"
    for rel in (".github/workflows/kept.yml", "ignored/.github/workflows/skipped.yml"):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(wf, encoding="utf-8")
    report = scan(tmp_path, ScanConfig(), now="2026-01-01T00:00:00+00:00")
    assert report.files_scanned == [".github/workflows/kept.yml"]


def test_self_hosted_runner_on_pr_flagged(tmp_path):
    report = _scan_tree(
        tmp_path,
        WF,
        "name: sh\non: pull_request\npermissions: {contents: read}\n"
        "jobs:\n  build:\n    runs-on: [self-hosted, linux]\n"
        "    steps:\n      - run: echo ok\n",
    )
    assert "self-hosted-pr" in {f.kind for f in report.findings}
