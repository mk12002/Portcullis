"""R6 — Step integrity: unauthenticated remote code entering the pipeline.

``curl … | bash`` executes whatever the remote host serves, with no integrity
check, inside a context that often holds credentials. Common in legitimate
setup scripts — so the finding surfaces the checksum-verification remediation
rather than condemning the pattern outright.
"""

from __future__ import annotations

import re

from portcullis.core.models import (
    Confidence,
    Finding,
    Pipeline,
    RuleMeta,
    ScanConfig,
    Severity,
)
from portcullis.rules.common import capped_confidence

RULES = [
    RuleMeta(
        rule_id="R6",
        name="Step integrity",
        summary=(
            "curl|bash-style install patterns, tool downloads without "
            "checksum verification, remote content piped into interpreters, "
            "and opting back into deprecated insecure workflow commands."
        ),
        fp_note=(
            "Legitimate setup scripts use these patterns constantly; the "
            "remediation is pinning + checksum verification, not removal."
        ),
    )
]

PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|\n;&]*\|\s*(?:sudo\s+)?(?:env\s+\S+\s+)?(?:bash|sh|zsh|python3?|perl|ruby|node)\b"
)
DOWNLOAD_RE = re.compile(r"\b(?:curl|wget)\b[^\n]*?(https?://[^\s'\"]+)")
CHECKSUM_RE = re.compile(r"sha(?:1|256|512)sum|shasum|gpg\s+--verify|cosign|minisign|--checksum")


UNSECURE_COMMANDS_KEY = "ACTIONS_ALLOW_UNSECURE_COMMANDS"


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes")


def check(pipeline: Pipeline, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    any_reachable = any(j.reachable_from_untrusted for j in pipeline.jobs)
    env_scopes: list[tuple[dict, str, int, str | None, str | None, bool]] = [
        (pipeline.env, "env", 1, None, None, any_reachable)
    ]
    for job in pipeline.jobs:
        env_scopes.append(
            (job.env, f"{job.key_path}.env", job.line, job.name, None, job.reachable_from_untrusted)
        )
        for step in job.steps:
            env_scopes.append(
                (
                    step.env,
                    f"{step.key_path}.env",
                    step.line,
                    job.name,
                    step.name,
                    job.reachable_from_untrusted,
                )
            )
    for env, key_path, line, job_name, step_name, reachable in env_scopes:
        if UNSECURE_COMMANDS_KEY in env and _truthy(env[UNSECURE_COMMANDS_KEY]):
            findings.append(
                Finding(
                    rule_id="R6",
                    kind="unsecure-commands",
                    message=(
                        f"{UNSECURE_COMMANDS_KEY} is enabled — it re-activates the "
                        "deprecated set-env/add-path workflow commands, which let "
                        "any step output rewrite the environment and PATH of later "
                        "steps."
                    ),
                    remediation=(
                        f"Remove {UNSECURE_COMMANDS_KEY}; use the $GITHUB_ENV / "
                        "$GITHUB_PATH files with validated, trusted values instead."
                    ),
                    file_path=pipeline.file_path,
                    line=line,
                    key_path=key_path,
                    job_name=job_name,
                    step_name=step_name,
                    base_severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence=f"{UNSECURE_COMMANDS_KEY}: true",
                    untrusted_reachable=reachable,
                )
            )

    for job in pipeline.jobs:
        for step in job.steps:
            if not step.run:
                continue
            verified = bool(CHECKSUM_RE.search(step.run))
            for line_no, text in step.run_lines():
                pipe = PIPE_TO_SHELL_RE.search(text)
                if pipe:
                    insecure_transport = "http://" in text
                    findings.append(
                        Finding(
                            rule_id="R6",
                            kind="curl-pipe-shell",
                            message=(
                                f"Step '{step.name}' pipes a remote download "
                                "directly into an interpreter"
                                + (" over plaintext HTTP" if insecure_transport else "")
                                + " — the pipeline executes whatever the remote "
                                "host serves, unverified."
                            ),
                            remediation=(
                                "Download to a file, verify a pinned checksum "
                                "(sha256sum -c) or signature, then execute; or "
                                "install from a pinned package."
                            ),
                            file_path=pipeline.file_path,
                            line=line_no,
                            key_path=step.key_path,
                            job_name=job.name,
                            step_name=step.name,
                            base_severity=Severity.HIGH if insecure_transport else Severity.MEDIUM,
                            confidence=capped_confidence(pipeline, Confidence.HIGH),
                            evidence=text.strip(),
                            untrusted_reachable=job.reachable_from_untrusted,
                        )
                    )
                    continue
                dl = DOWNLOAD_RE.search(text)
                if dl and not verified:
                    findings.append(
                        Finding(
                            rule_id="R6",
                            kind="unverified-download",
                            message=(
                                f"Step '{step.name}' downloads from {dl.group(1)} "
                                "with no checksum/signature verification visible in "
                                "this step."
                            ),
                            remediation=(
                                "Verify a pinned sha256 checksum or signature after "
                                "download, before use."
                            ),
                            file_path=pipeline.file_path,
                            line=line_no,
                            key_path=step.key_path,
                            job_name=job.name,
                            step_name=step.name,
                            base_severity=Severity.MEDIUM,
                            confidence=Confidence.LOW,
                            evidence=text.strip(),
                            untrusted_reachable=job.reachable_from_untrusted,
                        )
                    )
    return findings
