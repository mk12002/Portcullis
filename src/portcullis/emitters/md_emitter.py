"""Markdown emitter — a compact summary sized for PR comments and chat.

Same data as JSON/HTML, formatted as GitHub-flavored markdown: score line,
priority counts, a findings table, and remediation details in collapsible
sections. Deterministic like every other emitter.
"""

from __future__ import annotations

from portcullis.core.models import Report

_MAX_TABLE_ROWS = 30


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def emit_markdown(report: Report) -> str:
    counts = report.priority_counts
    lines: list[str] = []
    lines.append("## 🛡️ Portcullis — pipeline security report")
    lines.append("")
    lines.append(
        f"**Score: {report.score}/100** · "
        f"P0: **{counts['P0']}** · P1: **{counts['P1']}** · "
        f"P2: {counts['P2']} · P3: {counts['P3']} · "
        f"files scanned: {len(report.files_scanned)}"
    )
    lines.append("")
    lines.append(
        f"<sub>target `{_cell(report.target)}` · generated {report.generated_at} · "
        f"portcullis v{report.version} · {report.score_formula}</sub>"
    )
    lines.append("")

    if not report.findings:
        lines.append(
            "✅ **No findings.** All discovered pipeline files parse cleanly "
            "and match no detection rule."
        )
    else:
        lines.append(
            "| Priority | Rule | Location | Job | Severity | Confidence | Untrusted | Finding |"
        )
        lines.append("|---|---|---|---|---|---|---|---|")
        for f in report.findings[:_MAX_TABLE_ROWS]:
            sev = f.severity or f.base_severity
            pr = f.priority.name if f.priority is not None else "—"
            lines.append(
                f"| **{pr}** | {f.rule_id} `{_cell(f.kind)}` "
                f"| `{_cell(f.file_path)}:{f.line}` | {_cell(f.job_name or '—')} "
                f"| {sev.name}{' ↑' if f.escalated else ''} | {f.confidence.name} "
                f"| {'⚠️ yes' if f.untrusted_reachable else 'no'} | {_cell(f.message)} |"
            )
        if len(report.findings) > _MAX_TABLE_ROWS:
            lines.append("")
            lines.append(
                f"*…and {len(report.findings) - _MAX_TABLE_ROWS} more — see the full "
                "JSON/HTML report.*"
            )
        lines.append("")
        lines.append("<details><summary><b>Remediations</b></summary>")
        lines.append("")
        for f in report.findings:
            lines.append(
                f"- **{f.rule_id} `{_cell(f.kind)}`** at `{_cell(f.file_path)}:{f.line}` — "
                f"{_cell(f.remediation)}"
            )
        lines.append("")
        lines.append("</details>")

    if report.suppressed:
        lines.append("")
        lines.append(
            f"<sub>{len(report.suppressed)} finding(s) suppressed by inline "
            "`portcullis: ignore` comments.</sub>"
        )
    if report.skipped:
        lines.append("")
        lines.append("<details><summary>Warnings & notes</summary>")
        lines.append("")
        for entry in report.skipped:
            lines.append(f"- `{_cell(entry['file'])}` — {_cell(entry['reason'])}")
        lines.append("")
        lines.append("</details>")

    lines.append("")
    lines.append(
        "<sub>↑ = severity escalated one level because the job is reachable from an "
        "untrusted trigger. Static analysis approximates reachability — see the "
        "project README for limitations.</sub>"
    )
    return "\n".join(lines) + "\n"
