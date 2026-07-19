"""R5 — Secret exposure.

Three shapes: secrets reachable from untrusted-trigger jobs (the
exfiltration setup, corroborating R1), secrets written to logs or passed on
command lines, and plaintext credential-shaped strings hardcoded in pipeline
files. Detected plaintext values are redacted everywhere — evidence, JSON,
HTML, SARIF — and never printed.
"""

from __future__ import annotations

import re

from portcullis.core.models import (
    Confidence,
    Finding,
    Job,
    Pipeline,
    RuleMeta,
    ScanConfig,
    Severity,
    Step,
)
from portcullis.rules.common import (
    SECRETISH_NAME_RE,
    capped_confidence,
    looks_high_entropy,
    redact,
)

RULES = [
    RuleMeta(
        rule_id="R5",
        name="Secret exposure",
        summary=(
            "Secrets reachable from untrusted-trigger jobs, secrets echoed to "
            "logs or passed as command-line arguments, and plaintext "
            "credential-shaped strings hardcoded in pipeline files (redacted "
            "in all output)."
        ),
        fp_note=(
            "High-entropy detection also matches hashes and opaque IDs — such "
            "findings carry LOW confidence and surface without blocking. "
            "Values are always redacted."
        ),
    )
]

GITHUB_SECRET_EXPR_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
ECHO_RE = re.compile(r"^\s*(echo|printf|print)\b")
SHELL_SECRETISH_VAR_RE = re.compile(
    r"\$\{?([A-Za-z_][A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|CREDENTIAL)[A-Za-z0-9_]*)\}?",
    re.IGNORECASE,
)


def check(pipeline: Pipeline, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    for job in pipeline.jobs:
        if pipeline.platform == "github":
            findings.extend(_github_job(pipeline, job))
        else:
            findings.extend(_shell_echo_job(pipeline, job))
    findings.extend(_plaintext(pipeline))
    return findings


def _github_job(pipeline: Pipeline, job: Job) -> list[Finding]:
    findings: list[Finding] = []
    first_secret_use: tuple[Step, int] | None = None

    for step in job.steps:
        for line_no, text in step.run_lines():
            names = GITHUB_SECRET_EXPR_RE.findall(text)
            if not names:
                continue
            if first_secret_use is None:
                first_secret_use = (step, line_no)
            if ECHO_RE.match(text):
                findings.append(
                    Finding(
                        rule_id="R5",
                        kind="secret-echoed",
                        message=(
                            f"Secret(s) {', '.join(sorted(set(names)))} are written "
                            f"to the job log by an echo/print in job '{job.name}'. "
                            "Log masking is best-effort and fails on transformed "
                            "values."
                        ),
                        remediation=(
                            "Never print secret expressions; pass secrets via env: "
                            "to the consuming process and rely on masked, "
                            "non-printed usage."
                        ),
                        file_path=pipeline.file_path,
                        line=line_no,
                        key_path=step.key_path + ".run",
                        job_name=job.name,
                        step_name=step.name,
                        base_severity=Severity.HIGH,
                        confidence=capped_confidence(pipeline, Confidence.HIGH),
                        evidence=text.strip(),
                        untrusted_reachable=job.reachable_from_untrusted,
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule_id="R5",
                        kind="secret-cli-arg",
                        message=(
                            f"Secret(s) {', '.join(sorted(set(names)))} are "
                            f"interpolated into a command line in job '{job.name}' — "
                            "visible in process listings and error output."
                        ),
                        remediation=(
                            "Pass the secret via env: and let the tool read it from "
                            "the environment or a file, not argv."
                        ),
                        file_path=pipeline.file_path,
                        line=line_no,
                        key_path=step.key_path + ".run",
                        job_name=job.name,
                        step_name=step.name,
                        base_severity=Severity.MEDIUM,
                        confidence=capped_confidence(pipeline, Confidence.MEDIUM),
                        evidence=text.strip(),
                        untrusted_reachable=job.reachable_from_untrusted,
                    )
                )
        for value in list(step.env.values()) + list(step.with_.values()):
            if GITHUB_SECRET_EXPR_RE.search(str(value)) and first_secret_use is None:
                first_secret_use = (step, step.line)

    if job.reachable_from_untrusted and first_secret_use is not None:
        step, line_no = first_secret_use
        findings.append(
            Finding(
                rule_id="R5",
                kind="secret-untrusted-context",
                message=(
                    f"Job '{job.name}' uses repository secrets while reachable "
                    f"from an untrusted trigger ({job.untrusted_reason.split(':')[0]}). "
                    "Combined with attacker-influenced execution this is the "
                    "secret-exfiltration setup."
                ),
                remediation=(
                    "Move secret-using work to a workflow that runs only on "
                    "trusted events, or gate it behind environment protection "
                    "rules with required review."
                ),
                file_path=pipeline.file_path,
                line=line_no,
                key_path=step.key_path,
                job_name=job.name,
                step_name=step.name,
                base_severity=Severity.MEDIUM,
                confidence=capped_confidence(pipeline, Confidence.MEDIUM),
                evidence="secrets.* referenced in an untrusted-reachable job",
                untrusted_reachable=True,
            )
        )
    return findings


def _shell_echo_job(pipeline: Pipeline, job: Job) -> list[Finding]:
    """GitLab/Jenkins: echo of credential-looking shell variables."""
    findings: list[Finding] = []
    credential_vars = {
        k for k, v in pipeline.env.items() if str(v).startswith("credentials(")
    }
    for step in job.steps:
        for line_no, text in step.run_lines():
            if not ECHO_RE.match(text.strip()):
                continue
            hits = {m.group(1) for m in SHELL_SECRETISH_VAR_RE.finditer(text)}
            hits |= {v for v in credential_vars if re.search(r"\$\{?" + re.escape(v), text)}
            if hits:
                findings.append(
                    Finding(
                        rule_id="R5",
                        kind="secret-echoed",
                        message=(
                            f"Credential-looking variable(s) {', '.join(sorted(hits))} "
                            f"are echoed to the job log in '{job.name}'. CI log "
                            "masking is best-effort and often bypassed by "
                            "transformation."
                        ),
                        remediation=(
                            "Do not print credential variables; pass them directly "
                            "to the consuming tool via the environment."
                        ),
                        file_path=pipeline.file_path,
                        line=line_no,
                        key_path=step.key_path,
                        job_name=job.name,
                        step_name=step.name,
                        base_severity=Severity.HIGH,
                        confidence=capped_confidence(pipeline, Confidence.MEDIUM),
                        evidence=text.strip(),
                        untrusted_reachable=job.reachable_from_untrusted,
                    )
                )
    return findings


def _plaintext(pipeline: Pipeline) -> list[Finding]:
    """Hardcoded credential-shaped values in env/variables/with blocks."""
    findings: list[Finding] = []

    def scan_mapping(mapping, key_path: str, job: Job | None, line: int) -> None:
        for key, value in mapping.items():
            sval = str(value)
            if not looks_high_entropy(sval):
                continue
            secretish = bool(SECRETISH_NAME_RE.search(str(key)))
            findings.append(
                Finding(
                    rule_id="R5",
                    kind="plaintext-secret",
                    message=(
                        f"Variable '{key}' holds a high-entropy value hardcoded in "
                        "the pipeline file"
                        + (
                            " and its name suggests a credential."
                            if secretish
                            else "; it may be a hash or opaque ID (low confidence)."
                        )
                        + " Anyone with read access to the repository can read it."
                    ),
                    remediation=(
                        "Store the value in the CI system's secret store and "
                        "reference it; rotate the credential if it was real."
                    ),
                    file_path=pipeline.file_path,
                    line=line,
                    key_path=f"{key_path}.{key}",
                    job_name=job.name if job else None,
                    base_severity=Severity.MEDIUM,
                    confidence=capped_confidence(
                        pipeline, Confidence.MEDIUM if secretish else Confidence.LOW
                    ),
                    evidence=redact(str(key), sval),
                    untrusted_reachable=job.reachable_from_untrusted if job else False,
                )
            )

    scan_mapping(pipeline.env, "env", None, 1)
    for job in pipeline.jobs:
        scan_mapping(job.env, f"{job.key_path}.env", job, job.line)
        for step in job.steps:
            scan_mapping(step.env, f"{step.key_path}.env", job, step.line)
            scan_mapping(step.with_, f"{step.key_path}.with", job, step.line)
    return findings
