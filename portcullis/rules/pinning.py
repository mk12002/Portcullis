"""R3 — Action / image pinning.

A third-party action referenced by tag or branch (``@v3``, ``@main``) is a
mutable reference: whoever controls that repository (or compromises it) can
change what your pipeline executes. Pinning to a full commit SHA removes the
hijack vector at the cost of manual updates — a tradeoff the report states
rather than hiding.
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
from portcullis.rules.common import capped_confidence

RULES = [
    RuleMeta(
        rule_id="R3",
        name="Action / image pinning",
        summary=(
            "Actions and container images referenced by mutable tags or "
            "branches instead of commit SHAs / digests — a supply-chain "
            "hijack vector, weighted by first- vs third-party publisher."
        ),
        fp_note=(
            "SHA pinning trades away automatic updates; pair it with an "
            "update bot. First-party (actions/, github/) references are "
            "lower urgency, not zero."
        ),
    )
]

DEFAULT_FIRST_PARTY_PREFIXES = ("actions/", "github/")

SHA_REMEDIATION = (
    "Pin to a full commit SHA (uses: owner/action@<40-hex-sha> with a version "
    "comment) and update via a dependency bot; tags and branches are mutable."
)


def _is_first_party(raw: str, config: ScanConfig) -> bool:
    prefixes = DEFAULT_FIRST_PARTY_PREFIXES + tuple(config.trusted_action_prefixes)
    return any(raw.startswith(p) for p in prefixes)


def check(pipeline: Pipeline, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    for job in pipeline.jobs:
        for step in job.steps:
            uses = step.uses
            if uses is None or uses.is_local:
                continue
            if uses.name.startswith("docker://"):
                if not uses.raw.count("@sha256:"):
                    findings.append(
                        _image_finding(
                            pipeline, job, uses.raw, uses.line, step.key_path, "docker uses"
                        )
                    )
                continue
            if uses.is_sha_pinned:
                continue
            first_party = _is_first_party(uses.raw, config)
            ref_desc = f"@{uses.version}" if uses.version else "no version (defaults to the default branch)"
            findings.append(
                Finding(
                    rule_id="R3",
                    kind="unpinned-first-party" if first_party else "unpinned-third-party",
                    message=(
                        f"{'First-party' if first_party else 'Third-party'} action "
                        f"'{uses.name}' is pinned to a mutable reference "
                        f"({ref_desc}). A compromised or retagged release changes "
                        "what this pipeline executes."
                    ),
                    remediation=SHA_REMEDIATION,
                    file_path=pipeline.file_path,
                    line=uses.line,
                    key_path=step.key_path + ".uses",
                    job_name=job.name,
                    step_name=step.name,
                    base_severity=Severity.MEDIUM if first_party else Severity.HIGH,
                    confidence=capped_confidence(pipeline, Confidence.HIGH),
                    evidence=f"uses: {uses.raw}",
                    untrusted_reachable=job.reachable_from_untrusted,
                )
            )
        for image in job.images:
            if image.is_digest_pinned:
                continue
            if image.is_mutable_latest:
                findings.append(
                    _image_finding(
                        pipeline, job, image.image, image.line, job.key_path, image.context
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule_id="R3",
                        kind="image-pinned-tag",
                        message=(
                            f"Container image '{image.image}' ({image.context}) uses a "
                            "version tag; tags are mutable, a digest "
                            "(@sha256:…) is immutable."
                        ),
                        remediation="Pin the image to a digest: image@sha256:<digest>.",
                        file_path=pipeline.file_path,
                        line=image.line,
                        key_path=job.key_path,
                        job_name=job.name,
                        base_severity=Severity.LOW,
                        confidence=capped_confidence(pipeline, Confidence.HIGH),
                        evidence=f"image: {image.image}",
                        untrusted_reachable=job.reachable_from_untrusted,
                    )
                )
    return findings


def _image_finding(
    pipeline: Pipeline, job, image: str, line: int, key_path: str, context: str
) -> Finding:
    return Finding(
        rule_id="R3",
        kind="image-mutable-latest",
        message=(
            f"Container image '{image}' ({context}) resolves to whatever "
            "'latest'/the untagged default points at — fully mutable supply-chain "
            "input to this job."
        ),
        remediation="Pin the image to an immutable digest: image@sha256:<digest>.",
        file_path=pipeline.file_path,
        line=line,
        key_path=key_path,
        job_name=job.name,
        base_severity=Severity.MEDIUM,
        confidence=capped_confidence(pipeline, Confidence.HIGH),
        evidence=f"image: {image}",
        untrusted_reachable=job.reachable_from_untrusted,
    )
