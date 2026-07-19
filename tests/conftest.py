"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path

from portcullis.core.engine import scan
from portcullis.core.models import Finding, Report, ScanConfig

FIXTURES = Path(__file__).parent / "fixtures"
FIXED_NOW = "2026-01-01T00:00:00+00:00"


def scan_fixture(name: str, **config_kwargs) -> Report:
    return scan(FIXTURES / name, ScanConfig(**config_kwargs), now=FIXED_NOW)


def by_kind(report: Report) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {}
    for f in report.findings:
        out.setdefault(f.kind, []).append(f)
    return out


def line_of(fixture_rel: str, needle: str) -> int:
    """1-based line of the first line containing needle in a fixture file."""
    text = (FIXTURES / fixture_rel).read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"needle {needle!r} not found in {fixture_rel}")
