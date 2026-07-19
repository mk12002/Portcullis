"""R2 — Expression injection: untrusted context interpolated into shell/script.

The deepest rule. Uses core.taint for lightweight source→sink reachability:
an attacker-controllable context value (PR title, issue body, branch name…)
interpolated *directly* into a run/script line becomes part of the command
the shell parses. The safe pattern — routing through env: and referencing a
quoted shell variable — is never flagged and is the recommended remediation.
"""

from __future__ import annotations

import re

from portcullis.core import taint
from portcullis.core.models import (
    Confidence,
    Finding,
    Pipeline,
    RuleMeta,
    ScanConfig,
    Severity,
    Step,
)
from portcullis.rules.common import capped_confidence

RULES = [
    RuleMeta(
        rule_id="R2",
        name="Expression injection",
        summary=(
            "Attacker-controllable context (PR/issue titles and bodies, "
            "comments, head refs, commit messages, MR variables, CHANGE_* "
            "values) interpolated directly into a shell run/script line."
        ),
        fp_note=(
            "Interpolating trusted context (github.sha, github.repository) is "
            "safe and not flagged. The fix is routing the value through env: "
            "and referencing it as a quoted shell variable."
        ),
    )
]

GITHUB_REMEDIATION = (
    "Route the value through env: and reference it as a quoted shell variable, "
    'e.g. env: TITLE: ${{ <expr> }} then run: echo "$TITLE". The shell then '
    "receives the value as data, never as command text."
)


def check(pipeline: Pipeline, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    for job in pipeline.jobs:
        for step in job.steps:
            if pipeline.platform == "github":
                findings.extend(_github_step(pipeline, job.name, step, job))
            elif pipeline.platform == "gitlab":
                findings.extend(_gitlab_step(pipeline, job.name, step, job))
            elif pipeline.platform == "jenkins":
                findings.extend(_jenkins_step(pipeline, job.name, step, job))
    return findings


RUNNER_FILE_SINK_RE = re.compile(r"GITHUB_(ENV|OUTPUT|PATH)")


def _github_step(pipeline: Pipeline, job_name: str, step: Step, job) -> list[Finding]:
    findings = []
    for hit in taint.github_run_sinks(step):
        env_sink = RUNNER_FILE_SINK_RE.search(hit.snippet)
        findings.append(
            Finding(
                rule_id="R2",
                kind="env-injection" if env_sink else "expression-injection",
                message=(
                    (
                        f"Untrusted context '{hit.source}' is written to "
                        f"$GITHUB_{env_sink.group(1)} in job '{job_name}'. Crafted "
                        "multi-line input can define arbitrary environment "
                        "variables or PATH entries for every later step "
                        "(runner-file injection)."
                    )
                    if env_sink
                    else (
                        f"Untrusted context '{hit.source}' is interpolated directly "
                        f"into a run script in job '{job_name}'. Its value is expanded "
                        "before the shell parses the line, so crafted input becomes "
                        "part of the command."
                    )
                ),
                remediation=GITHUB_REMEDIATION,
                file_path=pipeline.file_path,
                line=hit.line,
                key_path=step.key_path + ".run",
                job_name=job_name,
                step_name=step.name,
                base_severity=Severity.HIGH,
                confidence=capped_confidence(pipeline, Confidence.HIGH),
                evidence=hit.snippet,
                untrusted_reachable=job.reachable_from_untrusted,
            )
        )
    if step.uses and step.uses.name == "actions/github-script":
        script = str(step.with_.get("script", ""))
        for m in taint.GITHUB_EXPR_RE.finditer(script):
            for source in taint.github_untrusted_sources(m.group(1)):
                findings.append(
                    Finding(
                        rule_id="R2",
                        kind="script-injection",
                        message=(
                            f"Untrusted context '{source.rstrip('.')}' is interpolated "
                            f"into a github-script body in job '{job_name}' — the value "
                            "is pasted into JavaScript source before evaluation."
                        ),
                        remediation=(
                            "Read the value inside the script from the context object "
                            "(e.g. context.payload.issue.title) instead of template "
                            "interpolation."
                        ),
                        file_path=pipeline.file_path,
                        line=step.line,
                        key_path=step.key_path + ".with.script",
                        job_name=job_name,
                        step_name=step.name,
                        base_severity=Severity.HIGH,
                        confidence=capped_confidence(pipeline, Confidence.HIGH),
                        evidence=m.group(0)[:120],
                        untrusted_reachable=job.reachable_from_untrusted,
                    )
                )
    return findings


def _gitlab_step(pipeline: Pipeline, job_name: str, step: Step, job) -> list[Finding]:
    findings = []
    for hit in taint.gitlab_script_sinks(step):
        findings.append(
            Finding(
                rule_id="R2",
                kind="variable-injection",
                message=(
                    f"MR-author-controlled variable {hit.expression} is expanded "
                    f"unquoted in a script line of job '{job_name}' — word "
                    "splitting and option injection are possible on crafted "
                    "titles/branch names."
                ),
                remediation=(
                    f'Always double-quote the expansion ("{hit.expression}") and '
                    "pass it as data, never build command text from it."
                ),
                file_path=pipeline.file_path,
                line=hit.line,
                key_path=step.key_path,
                job_name=job_name,
                step_name=step.name,
                base_severity=Severity.HIGH,
                confidence=capped_confidence(pipeline, Confidence.MEDIUM),
                evidence=hit.snippet,
                untrusted_reachable=job.reachable_from_untrusted,
            )
        )
    return findings


def _jenkins_step(pipeline: Pipeline, job_name: str, step: Step, job) -> list[Finding]:
    findings = []
    for hit in taint.jenkins_groovy_sinks(step):
        is_params = hit.source.startswith("params.")
        findings.append(
            Finding(
                rule_id="R2",
                kind="groovy-interpolation",
                message=(
                    f"'{hit.source}' is Groovy-interpolated into a double-quoted "
                    f"sh step in stage '{job_name}': the value is substituted into "
                    "the command string before the shell runs it (command "
                    "injection on attacker-controllable change-request values)."
                ),
                remediation=(
                    "Use a single-quoted Groovy string and read the value as a "
                    "shell environment variable (sh 'echo \"$CHANGE_TITLE\"'), so "
                    "the shell receives it as data."
                ),
                file_path=pipeline.file_path,
                line=hit.line,
                key_path=step.key_path,
                job_name=job_name,
                step_name=step.name,
                base_severity=Severity.HIGH,
                confidence=capped_confidence(
                    pipeline, Confidence.LOW if is_params else Confidence.MEDIUM
                ),
                evidence=hit.snippet,
                untrusted_reachable=job.reachable_from_untrusted,
            )
        )
    return findings
