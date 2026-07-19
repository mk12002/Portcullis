"""Checks added from the landscape review (zizmor/poutine/ARGUS gap analysis):
credential-persistence, artifact-poisoning, env-injection, secrets-inherit,
unsecure-commands, and inline suppressions."""

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


# --- R1 credential-persistence -------------------------------------------------

CHECKOUT_PR = """name: t
on: pull_request
permissions: {contents: read}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000001
      - run: echo ok
"""


def test_credential_persistence_flagged_on_pr_trigger(tmp_path):
    report = _scan(tmp_path, CHECKOUT_PR)
    ks = kinds(report)
    assert "credential-persistence" in ks
    f = ks["credential-persistence"][0]
    assert f.base_severity == Severity.LOW and f.confidence == Confidence.MEDIUM


def test_credential_persistence_quiet_when_disabled(tmp_path):
    fixed = CHECKOUT_PR.replace(
        "- uses: actions/checkout@0000000000000000000000000000000000000001",
        "- uses: actions/checkout@0000000000000000000000000000000000000001\n"
        "        with:\n          persist-credentials: false",
    )
    assert "credential-persistence" not in kinds(_scan(tmp_path, fixed))


def test_credential_persistence_quiet_on_push_only(tmp_path):
    assert "credential-persistence" not in kinds(
        _scan(tmp_path, CHECKOUT_PR.replace("on: pull_request", "on: push"))
    )


# --- R1 artifact-poisoning -----------------------------------------------------

def test_artifact_poisoning_on_workflow_run(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: workflow_run
permissions: {contents: read}
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@0000000000000000000000000000000000000001
      - run: echo processed
""",
    )
    ks = kinds(report)
    assert "artifact-poisoning" in ks
    assert ks["artifact-poisoning"][0].untrusted_reachable


def test_no_artifact_poisoning_on_push(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@0000000000000000000000000000000000000001
""",
    )
    assert "artifact-poisoning" not in kinds(report)


# --- R2 env-injection ----------------------------------------------------------

def test_env_injection_distinct_kind(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: pull_request
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_ENV
""",
    )
    ks = kinds(report)
    assert "env-injection" in ks
    assert "expression-injection" not in ks
    assert ks["env-injection"][0].base_severity == Severity.HIGH


# --- R4 secrets-inherit --------------------------------------------------------

def test_secrets_inherit_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  call:
    uses: example-org/flows/.github/workflows/x.yml@0000000000000000000000000000000000000001
    secrets: inherit
""",
    )
    ks = kinds(report)
    assert "secrets-inherit" in ks


def test_explicit_secrets_mapping_not_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  call:
    uses: example-org/flows/.github/workflows/x.yml@0000000000000000000000000000000000000001
    secrets:
      DEPLOY_KEY_NAME: ${{ secrets.FIXTURE_FAKE_DEPLOY_KEY }}
""",
    )
    assert "secrets-inherit" not in kinds(report)


# --- R6 unsecure-commands ------------------------------------------------------

def test_unsecure_commands_flagged(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    steps:
      - run: echo ok
""",
    )
    ks = kinds(report)
    assert "unsecure-commands" in ks
    assert ks["unsecure-commands"][0].job_name == "a"


# --- inline suppressions -------------------------------------------------------

def test_trailing_comment_suppresses_specific_rule(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: example-org/tool@v3 # portcullis: ignore[R3]
      - run: echo ok
""",
    )
    assert "unpinned-third-party" not in kinds(report)
    assert report.suppressed == [
        {"file": WF, "line": 8, "rule_id": "R3", "kind": "unpinned-third-party"}
    ]


def test_comment_above_suppresses_all_rules_on_next_line(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      # portcullis: ignore
      - uses: example-org/tool@v3
      - run: echo ok
""",
    )
    assert "unpinned-third-party" not in kinds(report)
    assert len(report.suppressed) == 1


def test_suppression_for_other_rule_does_not_apply(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: example-org/tool@v3 # portcullis: ignore[R6]
""",
    )
    assert "unpinned-third-party" in kinds(report)
    assert report.suppressed == []


def test_suppressed_findings_reported_in_json(tmp_path):
    report = _scan(
        tmp_path,
        """name: t
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: example-org/tool@v3 # portcullis: ignore[R3]
""",
    )
    data = report.to_dict()
    assert data["summary"]["suppressed_total"] == 1
    assert data["suppressed"][0]["rule_id"] == "R3"
