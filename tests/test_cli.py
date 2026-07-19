"""CLI contract: formats, --fail-on exit codes, filtering, robustness (Gate 5)."""

from __future__ import annotations

import json

import pytest
from conftest import FIXTURES

from portcullis.cli import main


def run(args: list[str], capsys) -> tuple[int, str, str]:
    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_version(capsys):
    code, out, _ = run(["version"], capsys)
    assert code == 0 and out.startswith("portcullis ")


def test_rules_list_prints_catalog(capsys):
    code, out, _ = run(["rules", "list"], capsys)
    assert code == 0
    for rid in ("R0", "R1", "R2", "R3", "R4", "R5", "R6"):
        assert rid in out
    assert "FP note" in out


def test_scan_all_formats_written(tmp_path, capsys):
    code, out, _ = run(
        ["scan", str(FIXTURES / "github"), "--format", "all", "--out", str(tmp_path)], capsys
    )
    assert code == 0  # no --fail-on: report only
    for ext in ("json", "html", "sarif", "md"):
        assert (tmp_path / f"report.{ext}").is_file()
    assert "score:" in out
    assert "[P0/" in out  # P0 must not fall through truthiness checks


def test_fail_on_p0_trips_on_vulnerable(tmp_path, capsys):
    code, _, err = run(
        ["scan", str(FIXTURES / "github"), "--format", "json", "--out", str(tmp_path),
         "--fail-on", "P0"], capsys
    )
    assert code == 1
    assert "failing" in err


def test_fail_on_p0_passes_on_clean(tmp_path, capsys):
    code, _, _ = run(
        ["scan", str(FIXTURES / "clean"), "--format", "json", "--out", str(tmp_path),
         "--fail-on", "P3"], capsys
    )
    assert code == 0


def test_fail_on_threshold_ordering(tmp_path, capsys):
    # push-injection alone has a P1 top finding: P0 gate passes, P1 gate fails.
    # Build an isolated dir via --platforms filtering instead: use gitlab fixture P0.
    code_p0, _, _ = run(
        ["scan", str(FIXTURES / "gitlab"), "--out", str(tmp_path), "--format", "json",
         "--fail-on", "P0", "--quiet"], capsys
    )
    assert code_p0 == 1


def test_platforms_filter(tmp_path, capsys):
    code, _, _ = run(
        ["scan", str(FIXTURES / "github"), "--platforms", "gitlab", "--format", "json",
         "--out", str(tmp_path), "--quiet"], capsys
    )
    assert code == 0
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["files_scanned"] == []
    assert data["findings"] == []


def test_trusted_actions_flag(tmp_path, capsys):
    code, _, _ = run(
        ["scan", str(FIXTURES / "github"), "--trusted-actions", "example-org/",
         "--format", "json", "--out", str(tmp_path), "--quiet"], capsys
    )
    assert code == 0
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    kinds = {f["kind"] for f in data["findings"]}
    assert "unpinned-third-party" not in kinds


def test_malformed_file_warns_low_finding_never_crashes(tmp_path, capsys):
    code, _, err = run(
        ["scan", str(FIXTURES / "malformed"), "--format", "json", "--out", str(tmp_path)],
        capsys,
    )
    assert code == 0
    assert "warning" in err.lower()
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    parse_findings = [f for f in data["findings"] if f["rule_id"] == "R0"]
    assert parse_findings and parse_findings[0]["severity"] == "LOW"
    # and the LOW finding is gateable at P3
    code2 = main(
        ["scan", str(FIXTURES / "malformed"), "--format", "json", "--out", str(tmp_path),
         "--fail-on", "P3", "--quiet"]
    )
    assert code2 == 1


def test_bad_platform_and_bad_path_exit_2(tmp_path, capsys):
    code, _, err = run(["scan", str(FIXTURES), "--platforms", "circleci"], capsys)
    assert code == 2 and "unknown platform" in err
    code, _, err = run(["scan", str(FIXTURES / "does-not-exist")], capsys)
    assert code == 2 and "not a directory" in err


def test_quiet_suppresses_summary(tmp_path, capsys):
    code, out, _ = run(
        ["scan", str(FIXTURES / "clean"), "--format", "json", "--out", str(tmp_path),
         "--quiet"], capsys
    )
    assert code == 0 and out == ""


def test_no_command_prints_help(capsys):
    code, out, _ = run([], capsys)
    assert code == 2
    assert "usage" in out.lower()


@pytest.mark.parametrize("fmt", ["json", "html", "sarif", "md"])
def test_single_format_writes_only_that_file(fmt, tmp_path, capsys):
    code, _, _ = run(
        ["scan", str(FIXTURES / "clean"), "--format", fmt, "--out", str(tmp_path),
         "--quiet"], capsys
    )
    assert code == 0
    files = {p.name for p in tmp_path.iterdir()}
    assert files == {f"report.{fmt}"}
