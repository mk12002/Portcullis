"""Jenkins: best-effort structural parse, honest confidence caps (Gate 3)."""

from __future__ import annotations

from conftest import by_kind, line_of, scan_fixture

from portcullis.core.models import Confidence, Priority, Severity


def test_expected_kinds_fire():
    kinds = by_kind(scan_fixture("jenkins"))
    for expected in (
        "pr-context-credentials",
        "groovy-interpolation",
        "image-mutable-latest",
        "secret-echoed",
        "curl-pipe-shell",
    ):
        assert expected in kinds, f"missing kind: {expected}"


def test_groovy_interpolation_detected_with_capped_confidence():
    kinds = by_kind(scan_fixture("jenkins"))
    inj = kinds["groovy-interpolation"][0]
    assert inj.job_name == "Build"
    assert inj.severity == Severity.CRITICAL and inj.escalated
    assert inj.confidence == Confidence.MEDIUM
    assert inj.line == line_of("jenkins/Jenkinsfile", "echo Building change")
    assert inj.priority == Priority.P0


def test_all_jenkins_confidence_capped_at_medium():
    report = scan_fixture("jenkins")
    assert report.findings, "expected findings on the jenkins fixture"
    assert all(f.confidence <= Confidence.MEDIUM for f in report.findings)


def test_best_effort_fidelity_note_present():
    report = scan_fixture("jenkins")
    assert any("best-effort" in entry["reason"] for entry in report.skipped)


def test_single_quoted_sh_not_flagged_as_injection():
    kinds = by_kind(scan_fixture("jenkins"))
    assert all("tool-setup" not in f.evidence for f in kinds["groovy-interpolation"])


def test_credential_echo_detected():
    kinds = by_kind(scan_fixture("jenkins"))
    echo = kinds["secret-echoed"][0]
    assert echo.job_name == "Deploy"
    assert "FIXTURE_FAKE_DEPLOY_TOKEN" in echo.evidence
