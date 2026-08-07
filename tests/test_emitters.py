"""Emitters: schema shape, byte-determinism, secret redaction (Gate 4)."""

from __future__ import annotations

import json

from conftest import scan_fixture

from portcullis.emitters import emit_html, emit_json, emit_markdown, emit_sarif

FAKE_SECRET_VALUE = "Fake9qWz3xVr7pLm2kJn8tBs4dCg6hYu"


def test_json_valid_and_deterministic():
    a = emit_json(scan_fixture("github"))
    b = emit_json(scan_fixture("github"))
    assert a == b
    data = json.loads(a)
    assert data["tool"]["name"] == "portcullis"
    assert data["summary"]["findings_total"] == len(data["findings"])
    assert data["summary"]["score_formula"].startswith("score =")


def test_html_deterministic_self_contained():
    a = emit_html(scan_fixture("github"))
    b = emit_html(scan_fixture("github"))
    assert a == b
    assert "<script src" not in a and "<link" not in a  # no external resources
    assert "Methodology" in a and "Limitations" in a
    assert "escalated: job reachable from an untrusted trigger" in a


def test_sarif_valid_and_deterministic():
    a = emit_sarif(scan_fixture("github"))
    b = emit_sarif(scan_fixture("github"))
    assert a == b
    sarif = json.loads(a)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"R0", "R1", "R2", "R3", "R4", "R5", "R6"}
    assert run["results"], "expected results for the vulnerable fixture"
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].endswith((".yml", ".yaml"))
        assert loc["region"]["startLine"] >= 1
        assert result["level"] in ("error", "warning", "note")


def test_p0_renders_as_p0_not_falsy_fallback():
    """Priority.P0 has value 0 — truthiness bugs would render it as '—'/'P3'."""
    report = scan_fixture("github")
    assert any(f.priority is not None and f.priority.name == "P0" for f in report.findings)
    html = emit_html(report)
    assert 'class="pill bg-P0">P0' in html
    sarif = json.loads(emit_sarif(report))
    assert any(r["properties"]["priority"] == "P0" for r in sarif["runs"][0]["results"])


def test_secret_value_redacted_in_all_formats():
    report = scan_fixture("gitlab")
    for emit in (emit_json, emit_html, emit_sarif, emit_markdown):
        assert FAKE_SECRET_VALUE not in emit(report)


def test_markdown_deterministic_and_pr_sized():
    a = emit_markdown(scan_fixture("github"))
    b = emit_markdown(scan_fixture("github"))
    assert a == b
    assert a.startswith("## 🛡️ Portcullis")
    assert "| Priority |" in a and "**P0**" in a
    assert "Remediations" in a
    clean = emit_markdown(scan_fixture("clean"))
    assert "No findings" in clean


def test_clean_fixture_scores_100_no_findings():
    report = scan_fixture("clean")
    assert report.findings == []
    assert report.score == 100
    assert sorted(report.platforms) == ["github", "gitlab", "jenkins"]
    html = emit_html(report)
    assert "no findings" in html


def test_gitlab_and_jenkins_reports_deterministic():
    for fixture in ("gitlab", "jenkins", "clean"):
        assert emit_json(scan_fixture(fixture)) == emit_json(scan_fixture(fixture))
        assert emit_sarif(scan_fixture(fixture)) == emit_sarif(scan_fixture(fixture))
        assert emit_html(scan_fixture(fixture)) == emit_html(scan_fixture(fixture))
