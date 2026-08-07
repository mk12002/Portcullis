"""The normalized pipeline model and finding/report types.

Every platform parser (GitHub Actions, GitLab CI, Jenkins) emits the same
``Pipeline`` structure, so each detection rule is written once against the
normal form instead of once per platform. This module depends on nothing
else inside Portcullis.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


class Severity(IntEnum):
    """Base severity of a finding. Ordered so escalation is ``value + 1``."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def escalated(self) -> Severity:
        """One level up, capped at CRITICAL (trigger-context escalation)."""
        return Severity(min(self.value + 1, Severity.CRITICAL.value))

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class Confidence(IntEnum):
    """How certain the rule is that the matched pattern is a real problem."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class Priority(IntEnum):
    """Action priority. Lower value = more urgent, so ascending sort puts P0 first."""

    P0 = 0
    P1 = 1
    P2 = 2
    P3 = 3

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class UsesRef:
    """A reference to an external action / reusable workflow (``uses:``)."""

    raw: str
    name: str  # e.g. "actions/checkout" or "./local/action"
    version: str | None  # text after "@", None if unversioned
    line: int

    @property
    def is_sha_pinned(self) -> bool:
        return bool(self.version and SHA40_RE.fullmatch(self.version))

    @property
    def is_local(self) -> bool:
        return self.name.startswith("./") or self.name.startswith(".\\")

    @property
    def owner(self) -> str:
        return self.name.split("/", 1)[0] if "/" in self.name else self.name


@dataclass
class ImageRef:
    """A container image reference (job container, service, GitLab image, Jenkins agent)."""

    image: str
    line: int
    context: str  # "container" | "service" | "image" | "agent"

    @property
    def is_digest_pinned(self) -> bool:
        return "@sha256:" in self.image

    @property
    def tag(self) -> str | None:
        if self.is_digest_pinned:
            return None
        # split off registry:port carefully: tag is after the last ":" past the last "/"
        tail = self.image.rsplit("/", 1)[-1]
        return tail.split(":", 1)[1] if ":" in tail else None

    @property
    def is_mutable_latest(self) -> bool:
        """Untagged or ``:latest`` — fully mutable."""
        return not self.is_digest_pinned and (self.tag is None or self.tag == "latest")


@dataclass
class Step:
    """One executable step of a job, normalized across platforms."""

    name: str
    line: int
    key_path: str
    index: int = 0
    uses: UsesRef | None = None
    run: str | None = None
    run_line: int = 0  # line of the run/script scalar (approximate for blocks)
    env: dict[str, Any] = field(default_factory=dict)
    with_: dict[str, Any] = field(default_factory=dict)
    shell: str | None = None  # e.g. "bash", "groovy-double", "groovy-single"
    # For reusable-workflow call pseudo-steps: the job-level `secrets:` value
    # ("inherit", a mapping, or None).
    secrets: Any = None

    def run_lines(self) -> list[tuple[int, str]]:
        """(approximate file line, text) for each line of the run script."""
        if not self.run:
            return []
        lines = self.run.splitlines() or [self.run]
        base = self.run_line or self.line
        if len(lines) > 1:
            # block scalar: content starts on the line after the key
            return [(base + 1 + i, ln) for i, ln in enumerate(lines)]
        return [(base, lines[0])]


@dataclass
class Trigger:
    """A pipeline trigger event with security-relevant classification."""

    event: str
    line: int = 0
    qualifiers: dict[str, Any] = field(default_factory=dict)
    # attacker-controllable input reaches the run AND it executes with access
    # to secrets / a privileged token (e.g. pull_request_target, workflow_run)
    untrusted_privileged: bool = False
    # attacker-controllable input reaches the run at all (includes pull_request)
    untrusted_input: bool = False


@dataclass
class Job:
    """A job: a set of steps that run together under one permission context."""

    name: str
    line: int
    key_path: str
    permissions: Any = None  # platform-shaped override ("write-all" | dict | None)
    permissions_line: int = 0
    steps: list[Step] = field(default_factory=list)
    condition: str | None = None
    runs_on: list[str] = field(default_factory=list)
    images: list[ImageRef] = field(default_factory=list)
    env: dict[str, Any] = field(default_factory=dict)
    matrix: bool = False
    # Computed at parse time from the pipeline's triggers; input to risk escalation.
    reachable_from_untrusted: bool = False
    untrusted_reason: str = ""


@dataclass
class Pipeline:
    """The normalized pipeline: what every platform parser emits."""

    platform: str  # "github" | "gitlab" | "jenkins"
    file_path: str  # POSIX-style path relative to the scan root
    triggers: list[Trigger] = field(default_factory=list)
    permissions: Any = None  # top-level permissions (platforms that support it)
    permissions_line: int = 0
    env: dict[str, Any] = field(default_factory=dict)
    jobs: list[Job] = field(default_factory=list)
    # what the platform can express; rules skip checks the platform can't answer
    capabilities: frozenset[str] = frozenset()
    # "full" for YAML platforms, "best-effort" for Jenkins/Groovy structural parse
    fidelity: str = "full"
    warnings: list[str] = field(default_factory=list)

    def untrusted_privileged_triggers(self) -> list[Trigger]:
        return [t for t in self.triggers if t.untrusted_privileged]


@dataclass(frozen=True)
class RuleMeta:
    """Catalog entry for ``portcullis rules list`` and the SARIF rules array."""

    rule_id: str
    name: str
    summary: str
    fp_note: str


@dataclass
class ScanConfig:
    """User-supplied scan configuration."""

    platforms: frozenset[str] = frozenset({"github", "gitlab", "jenkins"})
    trusted_action_prefixes: tuple[str, ...] = ()
    quiet: bool = False


@dataclass
class Finding:
    """One traceable detection: rule + evidence at a concrete file:line."""

    rule_id: str
    kind: str  # stable slug for the specific check, e.g. "expression-injection"
    message: str
    remediation: str
    file_path: str
    line: int
    key_path: str
    base_severity: Severity
    confidence: Confidence
    evidence: str = ""
    job_name: str | None = None
    step_name: str | None = None
    untrusted_reachable: bool = False
    # R1 findings are exempt: their base severity already encodes trigger context.
    escalatable: bool = True
    # Filled in by core.risk.assess():
    severity: Severity | None = None
    escalated: bool = False
    priority: Priority | None = None

    def sort_key(self) -> tuple:
        return (
            self.priority if self.priority is not None else Priority.P3,
            self.file_path,
            self.job_name or "",
            self.rule_id,
            self.line,
            self.kind,
            self.message,
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["base_severity"] = self.base_severity.name
        d["confidence"] = self.confidence.name
        d["severity"] = self.severity.name if self.severity is not None else None
        d["priority"] = self.priority.name if self.priority is not None else None
        d.pop("escalatable", None)
        return d


@dataclass
class Report:
    """Scan result: findings plus scoring and provenance metadata."""

    tool: str
    version: str
    target: str
    generated_at: str
    platforms: list[str]
    files_scanned: list[str]
    skipped: list[dict[str, str]]
    findings: list[Finding]
    score: int
    score_formula: str
    priority_counts: dict[str, int]
    # Findings dropped by inline `# portcullis: ignore[...]` comments.
    suppressed: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": self.tool, "version": self.version},
            "generated_at": self.generated_at,
            "target": self.target,
            "platforms": self.platforms,
            "files_scanned": self.files_scanned,
            "skipped": self.skipped,
            "summary": {
                "score": self.score,
                "score_formula": self.score_formula,
                "priority_counts": self.priority_counts,
                "findings_total": len(self.findings),
                "files_total": len(self.files_scanned),
                "suppressed_total": len(self.suppressed),
            },
            "findings": [f.to_dict() for f in self.findings],
            "suppressed": self.suppressed,
        }
