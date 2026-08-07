"""The Appendix-B risk truth table: priority must be a deterministic function
of (severity, confidence, untrusted-reachability, corroboration)."""

from __future__ import annotations

from portcullis.core import risk
from portcullis.core.models import Confidence, Finding, Priority, Severity


def make(
    rule_id: str,
    kind: str,
    severity: Severity,
    confidence: Confidence,
    job: str | None = "job",
    untrusted: bool = False,
    escalatable: bool = True,
    file: str = "wf.yml",
    line: int = 1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        kind=kind,
        message=f"{rule_id}:{kind}",
        remediation="fix",
        file_path=file,
        line=line,
        key_path="",
        base_severity=severity,
        confidence=confidence,
        job_name=job,
        untrusted_reachable=untrusted,
        escalatable=escalatable,
    )


def assess_one(f: Finding, *others: Finding) -> Finding:
    risk.assess([f, *others])
    return f


def test_r2_injection_in_untrusted_job_is_p0_critical():
    f = assess_one(
        make("R2", "expression-injection", Severity.HIGH, Confidence.HIGH, untrusted=True)
    )
    assert f.severity == Severity.CRITICAL and f.escalated
    assert f.priority == Priority.P0


def test_r1_pwn_plus_r5_secret_is_p0_both():
    r1 = make(
        "R1", "pwn-request", Severity.HIGH, Confidence.HIGH, untrusted=True, escalatable=False
    )
    r5 = make("R5", "secret-untrusted-context", Severity.MEDIUM, Confidence.MEDIUM, untrusted=True)
    risk.assess([r1, r5])
    assert r1.severity == Severity.CRITICAL and r1.priority == Priority.P0
    assert r5.severity == Severity.HIGH  # escalated MEDIUM
    assert r5.priority == Priority.P0  # corroboration bump from P1


def test_r5_secret_echoed_untrusted_is_p0():
    f = assess_one(make("R5", "secret-echoed", Severity.HIGH, Confidence.HIGH, untrusted=True))
    assert f.priority == Priority.P0


def test_r2_injection_on_trusted_trigger_is_p1():
    f = assess_one(make("R2", "expression-injection", Severity.HIGH, Confidence.HIGH))
    assert f.severity == Severity.HIGH and not f.escalated
    assert f.priority == Priority.P1


def test_r1_dangerous_trigger_alone_is_p1_not_escalated():
    f = assess_one(
        make(
            "R1",
            "dangerous-trigger",
            Severity.HIGH,
            Confidence.MEDIUM,
            job=None,
            untrusted=True,
            escalatable=False,
        )
    )
    assert f.severity == Severity.HIGH  # exempt from self-escalation
    assert f.priority == Priority.P1


def test_r3_third_party_mutable_tag_is_p1():
    f = assess_one(make("R3", "unpinned-third-party", Severity.HIGH, Confidence.HIGH))
    assert f.priority == Priority.P1


def test_r4_write_all_in_untrusted_job_is_p1():
    f = assess_one(make("R4", "write-all", Severity.MEDIUM, Confidence.HIGH, untrusted=True))
    assert f.severity == Severity.HIGH and f.escalated
    assert f.priority == Priority.P1


def test_r6_curl_bash_on_trusted_trigger_is_p2():
    f = assess_one(make("R6", "curl-pipe-shell", Severity.MEDIUM, Confidence.HIGH))
    assert f.priority == Priority.P2


def test_r3_first_party_tag_is_p2_and_never_corroborates():
    fp = make("R3", "unpinned-first-party", Severity.MEDIUM, Confidence.HIGH)
    other = make("R6", "curl-pipe-shell", Severity.MEDIUM, Confidence.HIGH)
    risk.assess([fp, other])
    assert fp.priority == Priority.P2  # hygiene kind: no corroboration bump


def test_r4_missing_permissions_low_risk_job_is_p2():
    f = assess_one(make("R4", "missing-permissions", Severity.MEDIUM, Confidence.MEDIUM))
    assert f.priority == Priority.P2


def test_two_independent_mediums_on_one_job_are_p1():
    a = make("R6", "curl-pipe-shell", Severity.MEDIUM, Confidence.HIGH)
    b = make("R4", "write-all", Severity.MEDIUM, Confidence.MEDIUM)
    risk.assess([a, b])
    assert a.priority == Priority.P1 and b.priority == Priority.P1


def test_corroboration_on_trusted_job_floors_at_p1_never_p0():
    # A HIGH third-party pin + MEDIUM broad-write on a manual-dispatch (trusted)
    # job: corroboration bumps, but must NOT reach the merge-blocking P0 bucket.
    r3 = make("R3", "unpinned-third-party", Severity.HIGH, Confidence.HIGH)
    r4 = make("R4", "broad-write", Severity.MEDIUM, Confidence.MEDIUM)
    risk.assess([r3, r4])
    assert r3.priority == Priority.P1  # P1 base, corroboration floored at P1
    assert r4.priority == Priority.P1  # P2 base bumped to P1


def test_corroboration_on_untrusted_job_can_reach_p0():
    # Same shape but the job is attacker-reachable: P0 is warranted.
    r3 = make("R3", "unpinned-third-party", Severity.HIGH, Confidence.HIGH, untrusted=True)
    r4 = make("R4", "broad-write", Severity.MEDIUM, Confidence.MEDIUM, untrusted=True)
    risk.assess([r3, r4])
    assert r3.severity == Severity.CRITICAL  # escalated HIGH→CRITICAL
    assert r3.priority == Priority.P0


def test_low_confidence_finding_is_capped_at_p3():
    f = assess_one(make("R5", "plaintext-secret", Severity.MEDIUM, Confidence.LOW))
    assert f.priority == Priority.P3
    g = assess_one(
        make("R2", "expression-injection", Severity.HIGH, Confidence.LOW, untrusted=True)
    )
    assert g.priority == Priority.P3  # even escalated severity: surface, don't block


def test_escalation_caps_at_critical():
    f = assess_one(make("R5", "secret-echoed", Severity.CRITICAL, Confidence.HIGH, untrusted=True))
    assert f.severity == Severity.CRITICAL


def test_corroboration_requires_two_distinct_rules():
    a = make("R5", "secret-echoed", Severity.MEDIUM, Confidence.MEDIUM, line=1)
    b = make("R5", "secret-cli-arg", Severity.MEDIUM, Confidence.MEDIUM, line=2)
    risk.assess([a, b])
    assert a.priority == Priority.P2 and b.priority == Priority.P2


def test_score_formula():
    p0 = make("R2", "expression-injection", Severity.HIGH, Confidence.HIGH, untrusted=True)
    p2 = make("R6", "curl-pipe-shell", Severity.MEDIUM, Confidence.HIGH, job="other")
    findings = risk.assess([p0, p2])
    assert risk.score(findings) == 100 - 30 - 5
    assert risk.score([]) == 100


def test_info_findings_do_not_reduce_score():
    f = make("R4", "note", Severity.INFO, Confidence.HIGH)
    findings = risk.assess([f])
    assert risk.score(findings) == 100
    assert risk.priority_counts(findings)["P3"] == 0
