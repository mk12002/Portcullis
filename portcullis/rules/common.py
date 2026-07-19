"""Helpers shared across rule modules."""

from __future__ import annotations

import math
import re
from collections import Counter

from portcullis.core.models import Confidence, Pipeline

SECRETISH_NAME_RE = re.compile(
    r"(?i)(secret|token|passwd|password|api[_-]?key|access[_-]?key|private[_-]?key|credential)"
)


def capped_confidence(pipeline: Pipeline, confidence: Confidence) -> Confidence:
    """Best-effort parses (Jenkins/Groovy) never claim HIGH confidence."""
    if pipeline.fidelity == "best-effort":
        return min(confidence, Confidence.MEDIUM)
    return confidence


def shannon_entropy(value: str) -> float:
    """Bits per character; used for plaintext-secret heuristics."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_high_entropy(value: str) -> bool:
    """Heuristic for a hardcoded credential-shaped string.

    Deliberately conservative (length >= 16, entropy >= 3.5, mixed character
    classes, not an expression); false positives on hashes/IDs are expected
    and are confidence-marked by the caller, never asserted as certain.
    """
    v = value.strip()
    if len(v) < 16 or len(v) > 512:
        return False
    if "${{" in v or v.startswith("$") or " " in v:
        return False
    # Paths, lists, URLs, and image refs are common high-entropy non-secrets
    # (e.g. "linux/amd64,linux/arm64", a project URL). A real credential is a
    # single opaque token, so reject values carrying these structural chars.
    if any(c in v for c in ("/", ",", "://", "\\")):
        return False
    classes = sum(
        1
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")
        if re.search(pattern, v)
    )
    return classes >= 3 and shannon_entropy(v) >= 3.5


# Keys whose values are structurally never secrets — excluded from plaintext
# scanning to cut false positives on real workflows (job/artifact names,
# image platforms, URLs, refs). Matched case-insensitively.
NON_SECRET_KEYS = frozenset(
    {
        "name",
        "platforms",
        "platform",
        "url",
        "project-url",
        "homepage",
        "repository",
        "image",
        "images",
        "tags",
        "tag",
        "path",
        "paths",
        "working-directory",
        "runs-on",
        "container",
        "title",
        "description",
        "ref",
        "branch",
        "tag-name",
        "version",
        "id",
        "uses",
        "runner",
        "labels",
    }
)


def is_non_secret_key(key: str) -> bool:
    return key.strip().lower() in NON_SECRET_KEYS


def redact(key: str, value: str) -> str:
    """Evidence text for a detected plaintext secret — value never included."""
    return f"{key}: [REDACTED — {len(value)} chars, high-entropy value]"
