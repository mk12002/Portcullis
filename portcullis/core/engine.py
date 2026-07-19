"""Scan orchestration: discover pipeline files → parse → rules → risk → Report.

Fully offline and static: files are read and parsed, never executed, and no
network access is performed. A file that fails to parse becomes a warning
plus a LOW R0 finding — one malformed workflow never aborts a scan.
"""

from __future__ import annotations

import fnmatch
import os
from datetime import UTC, datetime
from pathlib import Path

from portcullis import TOOL_NAME, __version__
from portcullis.core import risk
from portcullis.core.models import (
    Confidence,
    Finding,
    Report,
    ScanConfig,
    Severity,
)
from portcullis.platforms import ALL_PLATFORMS
from portcullis.platforms.base import ParseError
from portcullis.rules import ALL_RULE_MODULES


def _load_gitignore(root: Path) -> list[str]:
    path = root / ".gitignore"
    if not path.is_file():
        return []
    patterns = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("!"):
                patterns.append(line.rstrip("/"))
    except OSError:
        pass
    return patterns


def _ignored(rel_path: str, patterns: list[str]) -> bool:
    """Best-effort .gitignore matching (fnmatch on path segments; no negation)."""
    parts = rel_path.split("/")
    for pat in patterns:
        if "/" in pat:
            if fnmatch.fnmatch(rel_path, pat.lstrip("/")) or fnmatch.fnmatch(
                rel_path, pat.lstrip("/") + "/*"
            ):
                return True
        else:
            if any(fnmatch.fnmatch(part, pat) for part in parts):
                return True
    return False


def discover_files(root: Path) -> list[str]:
    """Repo-relative POSIX paths of all files under root, .git and .gitignore excluded."""
    patterns = _load_gitignore(root)
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        for name in sorted(filenames):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            if not _ignored(rel, patterns):
                found.append(rel)
    return sorted(found)


def scan(root: Path, config: ScanConfig | None = None, now: str | None = None) -> Report:
    config = config or ScanConfig()
    root = root.resolve()
    generated_at = now or datetime.now(UTC).isoformat(timespec="seconds")

    platforms = {
        name: platform
        for name, platform in ALL_PLATFORMS.items()
        if name in config.platforms
    }

    findings: list[Finding] = []
    files_scanned: list[str] = []
    skipped: list[dict[str, str]] = []
    platforms_seen: set[str] = set()

    for rel_path in discover_files(root):
        for name, platform in platforms.items():
            if not platform.matches(rel_path):
                continue
            files_scanned.append(rel_path)
            platforms_seen.add(name)
            full = root / rel_path
            try:
                text = full.read_bytes().decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                findings.append(_parse_finding(rel_path, f"unreadable file: {exc}"))
                skipped.append({"file": rel_path, "reason": str(exc)})
                break
            try:
                pipeline = platform.parse(text, rel_path)
            except ParseError as exc:
                findings.append(_parse_finding(rel_path, str(exc)))
                skipped.append({"file": rel_path, "reason": str(exc)})
                break
            except Exception as exc:  # defensive: no single file crashes a scan
                findings.append(_parse_finding(rel_path, f"unexpected parse failure: {exc}"))
                skipped.append({"file": rel_path, "reason": f"unexpected: {exc}"})
                break
            for module in ALL_RULE_MODULES:
                findings.extend(module.check(pipeline, config))
            for warning in pipeline.warnings:
                skipped.append({"file": rel_path, "reason": f"note: {warning}"})
            break  # a file belongs to exactly one platform

    risk.assess(findings)
    return Report(
        tool=TOOL_NAME,
        version=__version__,
        target=root.as_posix(),
        generated_at=generated_at,
        platforms=sorted(platforms_seen),
        files_scanned=files_scanned,
        skipped=skipped,
        findings=findings,
        score=risk.score(findings),
        score_formula=risk.SCORE_FORMULA,
        priority_counts=risk.priority_counts(findings),
    )


def _parse_finding(rel_path: str, reason: str) -> Finding:
    return Finding(
        rule_id="R0",
        kind="parse-error",
        message=(
            f"Pipeline file could not be parsed ({reason}). A malformed "
            "workflow may silently not run and is invisible to analysis."
        ),
        remediation="Fix the file so it parses; validate it with the platform's linter.",
        file_path=rel_path,
        line=1,
        key_path="",
        base_severity=Severity.LOW,
        confidence=Confidence.HIGH,
        evidence=reason[:200],
    )
