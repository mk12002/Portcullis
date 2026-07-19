"""The inertness guard (mandatory): fixtures must be vulnerable-looking but
harmless-acting. No functional exploit, no real secret, no live payload URL —
enforced automatically, per the inert-fixture law."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

import pytest

from portcullis.rules.common import looks_high_entropy

FIXTURES = Path(__file__).parent / "fixtures"
ALL_FIXTURE_FILES = sorted(p for p in FIXTURES.rglob("*") if p.is_file())

# Patterns that would indicate a functional exploit or real credential.
FORBIDDEN = [
    r"/dev/tcp/",
    r"\bnc\s+-e\b",
    r"\bbash\s+-i\b",
    r"base64\s+(-d|--decode)",
    r"\bmkfifo\b",
    r"AKIA[0-9A-Z]{16}",              # AWS access key id shape
    r"ghp_[A-Za-z0-9]{36}",           # GitHub PAT shape
    r"gh[oasr]_[A-Za-z0-9]{36}",
    r"xox[bpars]-",                   # Slack token shape
    r"-----BEGIN[A-Z ]*PRIVATE KEY",
    r"hooks\.slack\.com",
    r"curl[^\n]*secrets\.[A-Za-z0-9_]+[^\n]*https?://",  # secret exfil shape
]

# Only inert, reserved documentation domains may appear in fixtures.
ALLOWED_HOSTS = {"example.com", "www.example.com"}

INERT_MARKER = "INERT-BUT-VULNERABLE FIXTURE"
FAKE_MARKERS = ("fake", "fixture", "0000")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def test_fixture_files_exist():
    assert len(ALL_FIXTURE_FILES) >= 7


@pytest.mark.parametrize("path", ALL_FIXTURE_FILES, ids=lambda p: p.name)
def test_no_forbidden_patterns(path: Path):
    text = read(path)
    for pattern in FORBIDDEN:
        assert not re.search(pattern, text), f"{path}: forbidden pattern {pattern!r}"


@pytest.mark.parametrize("path", ALL_FIXTURE_FILES, ids=lambda p: p.name)
def test_only_inert_domains(path: Path):
    for url in re.findall(r"https?://[^\s'\")\]]+", read(path)):
        host = urlparse(url).hostname or ""
        assert host in ALLOWED_HOSTS, f"{path}: non-inert URL {url}"


@pytest.mark.parametrize("path", ALL_FIXTURE_FILES, ids=lambda p: p.name)
def test_high_entropy_strings_are_marked_fake(path: Path):
    # Slash/@/colon are excluded from tokens so action refs and image names
    # (actions/checkout@v4) don't read as credential-shaped strings.
    for token in re.findall(r"[A-Za-z0-9_\-+=]{16,}", read(path)):
        if looks_high_entropy(token):
            lowered = token.lower()
            assert any(m in lowered for m in FAKE_MARKERS), (
                f"{path}: high-entropy token without a fake/fixture marker: "
                f"[REDACTED {len(token)} chars]"
            )


def test_vulnerable_fixtures_carry_the_inert_marker():
    for sub in ("github", "gitlab", "jenkins"):
        for path in (FIXTURES / sub).rglob("*"):
            if path.is_file():
                assert INERT_MARKER in read(path), f"{path}: missing inert marker"


def test_injection_payloads_are_echo_only():
    """Every fixture line interpolating untrusted context must be an inert echo."""
    untrusted_bits = ("github.event.pull_request.title", "github.event.head_commit.message",
                      "CI_MERGE_REQUEST_TITLE", "CHANGE_TITLE")
    for path in ALL_FIXTURE_FILES:
        for line in read(path).splitlines():
            if any(bit in line for bit in untrusted_bits) and ("run:" in line or "sh " in line or line.strip().startswith("- ")):
                stripped = re.sub(r"^[\s\-]*", "", line)
                stripped = re.sub(r"^(run:\s*|sh\s+[\"']?)", "", stripped)
                assert stripped.startswith("echo") or "env:" in line or "ref:" in line, (
                    f"{path}: non-echo payload on untrusted interpolation: {line.strip()}"
                )
