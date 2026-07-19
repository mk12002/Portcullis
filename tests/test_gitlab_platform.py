"""GitLab CI: same rule modules, normalized model (Gate 3)."""

from __future__ import annotations

from conftest import by_kind, line_of, scan_fixture

from portcullis.core.models import Confidence, Priority, Severity

CI = ".gitlab-ci.yml"


def test_expected_kinds_fire():
    kinds = by_kind(scan_fixture("gitlab"))
    for expected in (
        "mr-untrusted-context",
        "variable-injection",
        "image-mutable-latest",
        "image-pinned-tag",
        "plaintext-secret",
        "secret-echoed",
        "curl-pipe-shell",
    ):
        assert expected in kinds, f"missing kind: {expected}"


def test_mr_injection_escalates():
    kinds = by_kind(scan_fixture("gitlab"))
    inj = kinds["variable-injection"][0]
    assert inj.job_name == "mr_lint"
    assert inj.severity == Severity.CRITICAL and inj.escalated
    assert inj.confidence == Confidence.MEDIUM  # quoting nuance: honest confidence
    assert inj.priority == Priority.P0
    assert inj.line == line_of(f"gitlab/{CI}", "$CI_MERGE_REQUEST_TITLE")


def test_build_job_not_untrusted():
    report = scan_fixture("gitlab")
    build_findings = [f for f in report.findings if f.job_name == "build"]
    assert all(not f.untrusted_reachable for f in build_findings)
    assert {f.kind for f in build_findings} == {"image-pinned-tag"}


def test_plaintext_secret_detected_and_redacted():
    report = scan_fixture("gitlab")
    kinds = by_kind(report)
    pt = kinds["plaintext-secret"][0]
    assert pt.key_path.endswith("FIXTURE_FAKE_API_TOKEN")
    assert pt.confidence == Confidence.MEDIUM  # secret-ish name
    assert "Fake9qWz3xVr7pLm2kJn8tBs4dCg6hYu" not in pt.evidence
    assert "REDACTED" in pt.evidence


def test_latest_image_flagged_versioned_tag_is_hygiene():
    kinds = by_kind(scan_fixture("gitlab"))
    latest = kinds["image-mutable-latest"][0]
    assert "node:latest" in latest.evidence
    tag = kinds["image-pinned-tag"][0]
    assert "python:3.11" in tag.evidence
    assert tag.priority == Priority.P3
