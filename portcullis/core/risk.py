"""Risk scoring: severity escalation, P0–P3 priority, and the 0–100 score.

The core insight encoded here: pipeline risk is contextual. The same
misconfiguration is far more dangerous inside a job reachable from an
untrusted trigger, so trigger-context escalation is applied first and is
first-class, then priority is a deterministic function of
(effective severity, confidence, corroborating rules on the same job).
"""

from __future__ import annotations

from collections import defaultdict

from portcullis.core.models import Confidence, Finding, Priority, Severity

SEVERITY_TO_PRIORITY: dict[Severity, Priority] = {
    Severity.CRITICAL: Priority.P0,
    Severity.HIGH: Priority.P1,
    Severity.MEDIUM: Priority.P2,
    Severity.LOW: Priority.P3,
    Severity.INFO: Priority.P3,
}

# Hygiene-class kinds never participate in (or receive) the corroboration bump:
# a first-party action on a tag next to a real issue should not become a P0.
HYGIENE_KINDS = {
    "unpinned-first-party",
    "image-pinned-tag",
    "image-mutable-latest",
    "parse-error",
}

SCORE_WEIGHTS: dict[Priority, int] = {
    Priority.P0: 30,
    Priority.P1: 15,
    Priority.P2: 5,
    Priority.P3: 1,
}

SCORE_FORMULA = (
    "score = max(0, 100 - 30*|P0| - 15*|P1| - 5*|P2| - 1*|P3|); INFO findings excluded"
)


def assess(findings: list[Finding]) -> list[Finding]:
    """Compute effective severity and priority for every finding, then sort.

    Deterministic, in this order:
      1. Trigger-context escalation: +1 severity inside an untrusted-reachable
         job (R1 findings exempt — their severity already encodes the trigger).
      2. R1 pwn-request synergy: CRITICAL when R2/R5 also fire on the same job
         (the classic secret-exfiltration setup).
      3. Severity → priority (CRITICAL=P0, HIGH=P1, MEDIUM=P2, LOW/INFO=P3).
      4. LOW confidence caps priority at P3: surface, don't block.
      5. Corroboration: >=2 distinct rules at MEDIUM+/MEDIUM+ on one job bump
         each participating finding one priority level.
    """
    for f in findings:
        if f.untrusted_reachable and f.escalatable and f.base_severity > Severity.INFO:
            f.severity = f.base_severity.escalated()
            f.escalated = f.severity != f.base_severity
        else:
            f.severity = f.base_severity
            f.escalated = False

    by_job: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        if f.job_name:
            by_job[(f.file_path, f.job_name)].append(f)

    for job_findings in by_job.values():
        rules_here = {f.rule_id for f in job_findings}
        if "R2" in rules_here or "R5" in rules_here:
            for f in job_findings:
                if f.rule_id == "R1" and f.kind == "pwn-request":
                    f.severity = Severity.CRITICAL
                    f.escalated = True

    for f in findings:
        assert f.severity is not None
        if f.confidence == Confidence.LOW:
            f.priority = Priority.P3
        else:
            f.priority = SEVERITY_TO_PRIORITY[f.severity]

    for job_findings in by_job.values():
        participants = [
            f
            for f in job_findings
            if f.severity is not None
            and f.severity >= Severity.MEDIUM
            and f.confidence >= Confidence.MEDIUM
            and f.kind not in HYGIENE_KINDS
        ]
        if len({f.rule_id for f in participants}) >= 2:
            for f in participants:
                assert f.priority is not None
                # Corroboration bumps one level, but P0 is reserved for
                # attacker-reachable criticals: on a trusted-trigger job it
                # floors at P1, so a pile of pinning + permission hygiene on a
                # manual-dispatch job never becomes a merge-blocking P0.
                floor = Priority.P0.value if f.untrusted_reachable else Priority.P1.value
                f.priority = Priority(max(floor, f.priority.value - 1))

    findings.sort(key=lambda f: f.sort_key())
    return findings


def score(findings: list[Finding]) -> int:
    """Pipeline security score 0–100 per SCORE_FORMULA. Higher is better."""
    total = 100
    for f in findings:
        if f.severity == Severity.INFO or f.priority is None:
            continue
        total -= SCORE_WEIGHTS[f.priority]
    return max(0, total)


def priority_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {p.name: 0 for p in Priority}
    for f in findings:
        if f.priority is not None and f.severity != Severity.INFO:
            counts[f.priority.name] += 1
    return counts
