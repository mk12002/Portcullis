"""R1 — Dangerous triggers.

The pwn-request pattern: a privileged untrusted trigger (pull_request_target,
workflow_run, issue/comment events) combined with a checkout of PR-head code
hands secrets and a privileged token to attacker-controlled code. R1 findings
are exempt from trigger-context escalation because their base severity already
encodes the trigger context; instead, pwn-request is raised to CRITICAL by
core.risk when R2/R5 corroborate on the same job.
"""

from __future__ import annotations

from portcullis.core.models import (
    Confidence,
    Finding,
    Pipeline,
    RuleMeta,
    ScanConfig,
    Severity,
)
from portcullis.platforms.github_actions import is_pr_head_checkout, is_self_hosted
from portcullis.rules.common import SECRETISH_NAME_RE, capped_confidence

RULES = [
    RuleMeta(
        rule_id="R1",
        name="Dangerous triggers",
        summary=(
            "Privileged workflows processing attacker-controllable input: "
            "pull_request_target/workflow_run checking out PR-head code "
            "(pwn-request), self-hosted runners exposed to PRs, and "
            "MR-triggered pipelines touching protected credentials."
        ),
        fp_note=(
            "pull_request_target is legitimate for labeling/triage that never "
            "touches PR code — reachability to a checkout of PR head is what "
            "escalates. Verify the job actually uses the untrusted input."
        ),
    )
]


def check(pipeline: Pipeline, config: ScanConfig) -> list[Finding]:
    if pipeline.platform == "github":
        return _check_github(pipeline)
    if pipeline.platform == "gitlab":
        return _check_gitlab(pipeline)
    if pipeline.platform == "jenkins":
        return _check_jenkins(pipeline)
    return []


def _check_github(pipeline: Pipeline) -> list[Finding]:
    findings: list[Finding] = []
    privileged = pipeline.untrusted_privileged_triggers()
    events = sorted({t.event for t in privileged})

    pwn_found = False
    if privileged:
        for job in pipeline.jobs:
            for step in job.steps:
                if is_pr_head_checkout(step):
                    pwn_found = True
                    findings.append(
                        Finding(
                            rule_id="R1",
                            kind="pwn-request",
                            message=(
                                f"Job '{job.name}' runs on {'/'.join(events)} (secrets "
                                "and a privileged token available) and checks out "
                                "PR-head code — attacker-controlled code executes in a "
                                "privileged context (pwn-request pattern)."
                            ),
                            remediation=(
                                "Split the workflow: handle untrusted PR code under the "
                                "unprivileged pull_request event, and keep "
                                "pull_request_target jobs from checking out PR-head refs. "
                                "If PR code must be processed, do it without secrets and "
                                "with permissions: read-all or less."
                            ),
                            file_path=pipeline.file_path,
                            line=step.line,
                            key_path=step.key_path,
                            job_name=job.name,
                            step_name=step.name,
                            base_severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            evidence=f"trigger {'/'.join(events)} + checkout of PR head at step '{step.name}'",
                            untrusted_reachable=True,
                            escalatable=False,
                        )
                    )
        if not pwn_found:
            for t in privileged:
                findings.append(
                    Finding(
                        rule_id="R1",
                        kind="dangerous-trigger",
                        message=(
                            f"Trigger '{t.event}' runs this workflow with secrets access "
                            "on attacker-controllable events. No PR-head checkout was "
                            "detected, but any future step that touches untrusted input "
                            "inherits this privileged context."
                        ),
                        remediation=(
                            "Prefer the unprivileged pull_request event where possible; "
                            "otherwise scope permissions to the minimum and never check "
                            "out or execute PR-controlled content in this workflow."
                        ),
                        file_path=pipeline.file_path,
                        line=t.line,
                        key_path=f"on.{t.event}",
                        base_severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        evidence=f"on: {t.event}",
                        untrusted_reachable=True,
                        escalatable=False,
                    )
                )

    if privileged or any(t.untrusted_input for t in pipeline.triggers):
        for job in pipeline.jobs:
            if is_self_hosted(job):
                findings.append(
                    Finding(
                        rule_id="R1",
                        kind="self-hosted-pr",
                        message=(
                            f"Job '{job.name}' runs on a self-hosted runner "
                            f"({', '.join(job.runs_on)}) in a workflow reachable from "
                            "PR-driven events. On a public repository this lets "
                            "external code run on persistent infrastructure "
                            "(persistence/lateral-movement risk)."
                        ),
                        remediation=(
                            "Use GitHub-hosted (ephemeral) runners for PR-triggered "
                            "workflows, or restrict the runner to trusted branches and "
                            "require approval for outside collaborators."
                        ),
                        file_path=pipeline.file_path,
                        line=job.line,
                        key_path=job.key_path,
                        job_name=job.name,
                        base_severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        evidence=f"runs-on: {', '.join(job.runs_on)}",
                        untrusted_reachable=job.reachable_from_untrusted,
                        escalatable=False,
                    )
                )
    return findings


def _check_gitlab(pipeline: Pipeline) -> list[Finding]:
    findings: list[Finding] = []
    for job in pipeline.jobs:
        if not job.reachable_from_untrusted:
            continue
        secretish = sorted(
            k
            for k in list(pipeline.env) + list(job.env)
            if SECRETISH_NAME_RE.search(k)
        )
        if secretish:
            findings.append(
                Finding(
                    rule_id="R1",
                    kind="mr-untrusted-context",
                    message=(
                        f"Job '{job.name}' runs on merge_request_event while the "
                        f"pipeline defines credential-looking variables "
                        f"({', '.join(secretish)}). MR-triggered jobs process "
                        "attacker-controllable input; exposing credentials to that "
                        "context is the exfiltration setup."
                    ),
                    remediation=(
                        "Mark sensitive variables as protected (branch-restricted) so "
                        "MR pipelines cannot read them, or split MR validation into a "
                        "job without credentials."
                    ),
                    file_path=pipeline.file_path,
                    line=job.line,
                    key_path=job.key_path,
                    job_name=job.name,
                    base_severity=Severity.MEDIUM,
                    confidence=capped_confidence(pipeline, Confidence.MEDIUM),
                    evidence=f"MR-triggered job + variables: {', '.join(secretish)}",
                    untrusted_reachable=True,
                    escalatable=False,
                )
            )
    return findings


def _check_jenkins(pipeline: Pipeline) -> list[Finding]:
    findings: list[Finding] = []
    untrusted = any(t.untrusted_privileged for t in pipeline.triggers)
    creds = sorted(k for k, v in pipeline.env.items() if str(v).startswith("credentials("))
    if untrusted and creds:
        job = pipeline.jobs[0] if pipeline.jobs else None
        findings.append(
            Finding(
                rule_id="R1",
                kind="pr-context-credentials",
                message=(
                    "Jenkinsfile binds credentials "
                    f"({', '.join(creds)}) while referencing change-request context "
                    "(CHANGE_*): multibranch PR builds expose these credentials to "
                    "jobs processing attacker-controllable input."
                ),
                remediation=(
                    "Move credential-using stages behind a trusted-branch condition "
                    "(when { not { changeRequest() } }) or a separate job that does "
                    "not build PR code."
                ),
                file_path=pipeline.file_path,
                line=job.line if job else 1,
                key_path=job.key_path if job else "",
                job_name=job.name if job else None,
                base_severity=Severity.MEDIUM,
                confidence=capped_confidence(pipeline, Confidence.MEDIUM),
                evidence=f"credentials bindings: {', '.join(creds)} + CHANGE_* context",
                untrusted_reachable=True,
                escalatable=False,
            )
        )
    return findings
