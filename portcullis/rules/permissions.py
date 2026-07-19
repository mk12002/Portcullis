"""R4 — Token permissions (platforms with a permissions model: GitHub Actions).

A workflow without an explicit ``permissions:`` block inherits the repository
default, which on many setups is broad write access. ``write-all`` grants the
job token every scope. Both are hygiene alone — and dangerous when the job is
reachable from an untrusted trigger, which trigger-context escalation encodes.
"""

from __future__ import annotations

from typing import Any

from portcullis.core.models import (
    Confidence,
    Finding,
    Pipeline,
    RuleMeta,
    ScanConfig,
    Severity,
)

RULES = [
    RuleMeta(
        rule_id="R4",
        name="Token permissions",
        summary=(
            "Missing explicit permissions block (broad default on many "
            "setups), write-all grants, over-broad write scopes on the job "
            "token, and blanket secrets: inherit into reusable workflows."
        ),
        fp_note=(
            "Some jobs legitimately need contents:write (release automation). "
            "The recommendation is an explicit least-privilege block, not "
            "removing needed scopes."
        ),
    )
]

LEAST_PRIVILEGE = (
    "Add an explicit least-privilege block, e.g. permissions: { contents: read } "
    "at the workflow top level, widening only the scopes a specific job needs."
)


def _is_write_all(perms: Any) -> bool:
    return isinstance(perms, str) and perms.strip() == "write-all"


def _write_scopes(perms: Any) -> list[str]:
    if not isinstance(perms, dict):
        return []
    return sorted(str(k) for k, v in perms.items() if str(v).strip() == "write")


def check(pipeline: Pipeline, config: ScanConfig) -> list[Finding]:
    if "permissions" not in pipeline.capabilities:
        return []
    findings: list[Finding] = []
    any_reachable = any(j.reachable_from_untrusted for j in pipeline.jobs)

    if pipeline.permissions is None and pipeline.jobs:
        jobs_without_own = [j for j in pipeline.jobs if j.permissions is None]
        if jobs_without_own:
            findings.append(
                Finding(
                    rule_id="R4",
                    kind="missing-permissions",
                    message=(
                        "No explicit permissions block at the workflow level and "
                        f"{len(jobs_without_own)} job(s) without their own — the "
                        "token falls back to the repository default, which is "
                        "broad write access on many setups."
                    ),
                    remediation=LEAST_PRIVILEGE,
                    file_path=pipeline.file_path,
                    line=1,
                    key_path="permissions",
                    base_severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence="no permissions: block present",
                    untrusted_reachable=any_reachable,
                )
            )

    if _is_write_all(pipeline.permissions):
        findings.append(
            _write_all_finding(
                pipeline,
                line=pipeline.permissions_line or 1,
                key_path="permissions",
                job_name=None,
                untrusted=any_reachable,
                where="workflow",
            )
        )
    for job in pipeline.jobs:
        if _is_write_all(job.permissions):
            findings.append(
                _write_all_finding(
                    pipeline,
                    line=job.permissions_line or job.line,
                    key_path=f"{job.key_path}.permissions",
                    job_name=job.name,
                    untrusted=job.reachable_from_untrusted,
                    where=f"job '{job.name}'",
                )
            )
        scopes = _write_scopes(job.permissions)
        if len(scopes) >= 3:
            findings.append(
                Finding(
                    rule_id="R4",
                    kind="broad-write",
                    message=(
                        f"Job '{job.name}' grants write on {len(scopes)} scopes "
                        f"({', '.join(scopes)}) — wider than most jobs need."
                    ),
                    remediation=LEAST_PRIVILEGE,
                    file_path=pipeline.file_path,
                    line=job.permissions_line or job.line,
                    key_path=f"{job.key_path}.permissions",
                    job_name=job.name,
                    base_severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence=f"write scopes: {', '.join(scopes)}",
                    untrusted_reachable=job.reachable_from_untrusted,
                )
            )
    for job in pipeline.jobs:
        for step in job.steps:
            if step.uses and isinstance(step.secrets, str) and step.secrets.strip() == "inherit":
                findings.append(
                    Finding(
                        rule_id="R4",
                        kind="secrets-inherit",
                        message=(
                            f"Job '{job.name}' forwards every repository secret to "
                            f"the reusable workflow '{step.uses.raw}' via "
                            "secrets: inherit — the called workflow (and anything "
                            "it is compromised by) receives all of them."
                        ),
                        remediation=(
                            "Pass only the specific secrets the called workflow "
                            "needs as an explicit secrets: mapping."
                        ),
                        file_path=pipeline.file_path,
                        line=step.line,
                        key_path=f"{job.key_path}.secrets",
                        job_name=job.name,
                        step_name=step.name,
                        base_severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        evidence=f"secrets: inherit → {step.uses.raw}",
                        untrusted_reachable=job.reachable_from_untrusted,
                    )
                )

    top_scopes = _write_scopes(pipeline.permissions)
    if len(top_scopes) >= 3:
        findings.append(
            Finding(
                rule_id="R4",
                kind="broad-write",
                message=(
                    f"Workflow grants write on {len(top_scopes)} scopes "
                    f"({', '.join(top_scopes)}) to every job."
                ),
                remediation=LEAST_PRIVILEGE,
                file_path=pipeline.file_path,
                line=pipeline.permissions_line or 1,
                key_path="permissions",
                base_severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence=f"write scopes: {', '.join(top_scopes)}",
                untrusted_reachable=any_reachable,
            )
        )
    return findings


def _write_all_finding(
    pipeline: Pipeline, line: int, key_path: str, job_name, untrusted: bool, where: str
) -> Finding:
    return Finding(
        rule_id="R4",
        kind="write-all",
        message=(
            f"permissions: write-all on {where} grants the token every scope "
            "(contents, packages, actions, id-token…) — far more than any "
            "single job needs."
        ),
        remediation=LEAST_PRIVILEGE,
        file_path=pipeline.file_path,
        line=line,
        key_path=key_path,
        job_name=job_name,
        base_severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        evidence="permissions: write-all",
        untrusted_reachable=untrusted,
    )
