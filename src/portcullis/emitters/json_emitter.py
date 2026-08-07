"""Canonical JSON emitter: deterministic ordering, sorted keys, stable layout."""

from __future__ import annotations

import json

from portcullis.core.models import Report


def emit_json(report: Report) -> str:
    """Byte-deterministic for identical input (generated_at excepted by design)."""
    return json.dumps(report.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
