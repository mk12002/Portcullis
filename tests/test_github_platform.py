"""GitHub Actions end-to-end: exact rule firings on the inert fixture,
including the trigger-context escalation contrast (Gate 2)."""

from __future__ import annotations

from conftest import FIXTURES, by_kind, line_of, scan_fixture

from portcullis.core.models import Confidence, Priority, Severity
from portcullis.platforms.github_actions import GitHubActionsPlatform

VULN = ".github/workflows/vulnerable.yml"
PUSH = ".github/workflows/push-injection.yml"


def test_discovers_both_workflows():
    report = scan_fixture("github")
    assert sorted(report.files_scanned) == [PUSH, VULN]
    assert report.platforms == ["github"]


def test_all_expected_kinds_fire():
    kinds = by_kind(scan_fixture("github"))
    for expected in (
        "pwn-request",
        "expression-injection",
        "secret-echoed",
        "secret-untrusted-context",
        "unpinned-third-party",
        "unpinned-first-party",
        "write-all",
        "curl-pipe-shell",
    ):
        assert expected in kinds, f"missing kind: {expected}"


def test_escalation_contrast_same_injection_higher_under_pull_request_target():
    kinds = by_kind(scan_fixture("github"))
    injections = {f.file_path: f for f in kinds["expression-injection"]}
    prt = injections[VULN]
    push = injections[PUSH]
    assert prt.severity == Severity.CRITICAL and prt.escalated
    assert prt.priority == Priority.P0
    assert push.severity == Severity.HIGH and not push.escalated
    assert push.priority == Priority.P1
    assert prt.confidence == Confidence.HIGH


def test_pwn_request_critical_with_corroborating_rules():
    kinds = by_kind(scan_fixture("github"))
    pwn = kinds["pwn-request"][0]
    assert pwn.job_name == "triage"
    assert pwn.severity == Severity.CRITICAL  # R2/R5 on the same job
    assert pwn.priority == Priority.P0
    assert pwn.line == line_of(f"github/{VULN}", "uses: actions/checkout@v4")


def test_secret_echoed_is_p0_in_untrusted_context():
    kinds = by_kind(scan_fixture("github"))
    echoed = kinds["secret-echoed"][0]
    assert echoed.severity == Severity.CRITICAL and echoed.escalated
    assert echoed.priority == Priority.P0
    assert "FIXTURE_FAKE_WEBHOOK_TOKEN" in echoed.evidence


def test_write_all_escalates_to_p1():
    kinds = by_kind(scan_fixture("github"))
    wa = kinds["write-all"][0]
    assert wa.severity == Severity.HIGH and wa.escalated
    assert wa.priority == Priority.P1
    assert wa.line == line_of(f"github/{VULN}", "permissions: write-all")


def test_third_party_pinning_flagged_first_party_lower():
    kinds = by_kind(scan_fixture("github"))
    third = kinds["unpinned-third-party"][0]
    assert "example-org/super-linter" in third.evidence
    assert third.base_severity == Severity.HIGH
    firsts = {f.evidence for f in kinds["unpinned-first-party"]}
    assert any("actions/checkout@v4" in e for e in firsts)
    assert any("actions/setup-python@v5" in e for e in firsts)
    for f in kinds["unpinned-first-party"]:
        assert f.base_severity == Severity.MEDIUM


def test_finding_lines_are_accurate():
    kinds = by_kind(scan_fixture("github"))
    inj = [f for f in kinds["expression-injection"] if f.file_path == VULN][0]
    assert inj.line == line_of(f"github/{VULN}", "github.event.pull_request.title")
    curl = kinds["curl-pipe-shell"][0]
    assert curl.line == line_of(f"github/{VULN}", "curl -sSL")


def test_matrix_job_parsed_and_matrix_context_not_flagged():
    platform = GitHubActionsPlatform()
    text = (FIXTURES / "github" / VULN).read_text(encoding="utf-8")
    pipeline = platform.parse(text, VULN)
    jobs = {j.name: j for j in pipeline.jobs}
    assert jobs["matrix-build"].matrix
    assert jobs["triage"].reachable_from_untrusted
    kinds = by_kind(scan_fixture("github"))
    assert all(f.job_name != "matrix-build" for f in kinds["expression-injection"])


def test_trusted_actions_flag_reclassifies_third_party():
    report = scan_fixture("github", trusted_action_prefixes=("example-org/",))
    kinds = by_kind(report)
    assert "unpinned-third-party" not in kinds
    assert any("super-linter" in f.evidence for f in kinds["unpinned-first-party"])


def test_vulnerable_fixture_scores_low():
    assert scan_fixture("github").score <= 20
