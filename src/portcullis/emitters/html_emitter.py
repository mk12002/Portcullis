"""Self-contained HTML report: inline CSS, zero external requests.

Structure (per the report contract): header → executive band (score +
formula, priority counts, headline) → priority table with confidence and
untrusted-reachability visibly marked → per-file breakdown → full findings
with remediation → methodology & limitations footer. Every number comes from
real findings; detected secret values are already redacted upstream.
"""

from __future__ import annotations

import html
from collections import defaultdict

from portcullis.core.models import Finding, Priority, Report

_CSS = """
:root { --bg:#12151a; --panel:#1b2027; --line:#2b323c; --text:#e6e9ed; --muted:#9aa4b2;
  --p0:#e5484d; --p1:#e8883a; --p2:#d8b135; --p3:#6f7d8f; --ok:#46a758; --accent:#4f8cc9; }
* { box-sizing:border-box; }
body { margin:0; font:15px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  background:var(--bg); color:var(--text); }
.wrap { max-width:1100px; margin:0 auto; padding:32px 24px 64px; }
header h1 { font-size:22px; margin:0 0 4px; letter-spacing:.02em; }
header .meta { color:var(--muted); font-size:13px; }
.band { display:flex; gap:16px; flex-wrap:wrap; margin:28px 0; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:18px 22px; }
.score { min-width:180px; text-align:center; }
.score .num { font-size:44px; font-weight:700; line-height:1.1; }
.score .formula { color:var(--muted); font-size:11px; margin-top:8px; max-width:220px; }
.counts { display:flex; gap:14px; align-items:center; flex-wrap:wrap; }
.pill { border-radius:999px; padding:3px 12px; font-weight:600; font-size:13px; color:#fff; }
.bg-P0{background:var(--p0);} .bg-P1{background:var(--p1);} .bg-P2{background:var(--p2);color:#1b1b1b;}
.bg-P3{background:var(--p3);} .bg-OK{background:var(--ok);}
.headline { flex:1 1 320px; }
.headline .lead { font-size:15px; }
h2 { font-size:17px; margin:36px 0 12px; border-bottom:1px solid var(--line); padding-bottom:6px; }
table { border-collapse:collapse; width:100%; font-size:13.5px; }
th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }
.tag { display:inline-block; border-radius:5px; padding:1px 7px; font-size:11.5px; font-weight:600; }
.flag { color:var(--p0); font-weight:700; }
.conf-LOW{color:var(--muted);} .conf-MEDIUM{color:var(--p2);} .conf-HIGH{color:var(--ok);}
.finding { background:var(--panel); border:1px solid var(--line); border-left-width:4px;
  border-radius:8px; padding:14px 18px; margin:12px 0; }
.finding.P0{border-left-color:var(--p0);} .finding.P1{border-left-color:var(--p1);}
.finding.P2{border-left-color:var(--p2);} .finding.P3{border-left-color:var(--p3);}
.finding .loc { font-family:Consolas,Menlo,monospace; font-size:12.5px; color:var(--accent); }
.finding .evidence { font-family:Consolas,Menlo,monospace; font-size:12.5px; background:#10131a;
  border:1px solid var(--line); border-radius:6px; padding:8px 10px; margin:8px 0;
  white-space:pre-wrap; word-break:break-all; color:#c8d1dc; }
.finding .rem { color:var(--muted); font-size:13.5px; }
.finding .rem b { color:var(--text); }
footer { margin-top:48px; color:var(--muted); font-size:12.5px; border-top:1px solid var(--line); padding-top:16px; }
footer ul { margin:6px 0 0 18px; padding:0; }
.scroll { overflow-x:auto; }
"""

_LIMITATIONS = [
    "Static YAML/structure analysis cannot always prove that untrusted input "
    "actually reaches a sink at runtime — confidence levels mark that honestly.",
    "Reusable/called workflows are followed shallowly: the reference is "
    "analyzed, not the called workflow's content.",
    "Jenkinsfile (Groovy) parsing is best-effort structural extraction; "
    "findings there are capped at MEDIUM confidence.",
    "High-entropy plaintext-secret detection has false positives (hashes, "
    "opaque IDs); such findings carry LOW confidence. Detected values are "
    "redacted everywhere.",
    "A clean scan is evidence of hygiene, not proof of security.",
]


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _headline(report: Report) -> str:
    if not report.findings:
        return (
            "No findings. All discovered pipeline files parse cleanly and match no detection rule."
        )
    top = report.findings[0]
    if top.priority == Priority.P0:
        return f"{report.priority_counts['P0']} finding(s) at P0 — most urgent: {top.message}"
    return f"Most urgent finding ({top.priority.name if top.priority is not None else '—'}): {top.message}"


def emit_html(report: Report) -> str:
    counts = report.priority_counts
    parts: list[str] = []
    parts.append(
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        # Defense-in-depth: all finding evidence is HTML-escaped, but the report
        # is built from untrusted pipeline content, so a strict CSP forbids any
        # script execution and any network request. The report is fully
        # self-contained (inline CSS only), so this never breaks rendering.
        '<meta http-equiv="Content-Security-Policy" content="'
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\">"
        f"<title>Portcullis report — {_esc(report.target)}</title>"
        f'<style>{_CSS}</style></head><body><div class="wrap">'
    )
    parts.append(
        f"<header><h1>Portcullis — pipeline security report</h1>"
        f'<div class="meta">target: <code>{_esc(report.target)}</code> · '
        f"generated: {_esc(report.generated_at)} · portcullis v{_esc(report.version)} · "
        f"platforms: {_esc(', '.join(report.platforms) or 'none detected')} · "
        f"files scanned: {len(report.files_scanned)}</div></header>"
    )

    pills = "".join(
        f'<span class="pill bg-{p}">{p}: {counts[p]}</span>' for p in ("P0", "P1", "P2", "P3")
    )
    parts.append(
        '<div class="band">'
        f'<div class="card score"><div class="num">{report.score}<span style="font-size:18px;color:var(--muted)">/100</span></div>'
        "<div>pipeline security score</div>"
        f'<div class="formula">{_esc(report.score_formula)}</div></div>'
        f'<div class="card headline"><div class="counts">{pills}</div>'
        f'<p class="lead">{_esc(_headline(report))}</p></div></div>'
    )

    # Priority table
    parts.append(
        '<h2>Findings overview</h2><div class="scroll"><table><thead><tr>'
        "<th>Priority</th><th>Rule</th><th>File</th><th>Job</th><th>Severity</th>"
        "<th>Confidence</th><th>Untrusted-reachable</th><th>Finding</th></tr></thead><tbody>"
    )
    if not report.findings:
        parts.append(
            '<tr><td colspan="8"><span class="pill bg-OK">clean</span> no findings</td></tr>'
        )
    for f in report.findings:
        sev = f.severity or f.base_severity
        pr_name = f.priority.name if f.priority is not None else "P3"
        esc_marker = ' <span class="flag">&#8593;</span>' if f.escalated else ""
        reach = '<span class="flag">YES</span>' if f.untrusted_reachable else "no"
        parts.append(
            "<tr>"
            f'<td><span class="pill bg-{pr_name}">{pr_name}</span></td>'
            f'<td>{_esc(f.rule_id)}<br><span style="color:var(--muted);font-size:11px">{_esc(f.kind)}</span></td>'
            f"<td><code>{_esc(f.file_path)}:{f.line}</code></td>"
            f"<td>{_esc(f.job_name or '—')}</td>"
            f"<td>{_esc(sev.name)}{esc_marker}</td>"
            f'<td class="conf-{f.confidence.name}">{_esc(f.confidence.name)}</td>'
            f"<td>{reach}</td>"
            f"<td>{_esc(f.message)}</td></tr>"
        )
    parts.append("</tbody></table></div>")

    # Per-file breakdown
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in report.findings:
        by_file[f.file_path].append(f)
    parts.append(
        '<h2>Per-file breakdown</h2><div class="scroll"><table><thead><tr>'
        "<th>File</th><th>P0</th><th>P1</th><th>P2</th><th>P3</th></tr></thead><tbody>"
    )
    for path in report.files_scanned:
        fs = by_file.get(path, [])
        row = {
            p: sum(1 for f in fs if f.priority is not None and f.priority.name == p)
            for p in ("P0", "P1", "P2", "P3")
        }
        parts.append(
            f"<tr><td><code>{_esc(path)}</code></td>"
            + "".join(f"<td>{row[p] or '·'}</td>" for p in ("P0", "P1", "P2", "P3"))
            + "</tr>"
        )
    parts.append("</tbody></table></div>")

    # Full findings
    parts.append("<h2>Full findings</h2>")
    if not report.findings:
        parts.append('<p><span class="pill bg-OK">clean</span> Nothing to remediate.</p>')
    for f in report.findings:
        sev = f.severity or f.base_severity
        pr = f.priority.name if f.priority is not None else "P3"
        escalation_note = (
            ' <span class="flag">(escalated: job reachable from an untrusted trigger)</span>'
            if f.escalated
            else ""
        )
        parts.append(
            f'<div class="finding {pr}">'
            f'<div><span class="pill bg-{pr}">{pr}</span> '
            f"<b>{_esc(f.rule_id)} · {_esc(f.kind)}</b> — {_esc(sev.name)} severity, "
            f'<span class="conf-{f.confidence.name}">{_esc(f.confidence.name)} confidence</span>'
            f"{escalation_note}</div>"
            f'<div class="loc">{_esc(f.file_path)}:{f.line}'
            + (f" · {_esc(f.key_path)}" if f.key_path else "")
            + (f" · job <b>{_esc(f.job_name)}</b>" if f.job_name else "")
            + "</div>"
            f"<p>{_esc(f.message)}</p>"
            + (f'<div class="evidence">{_esc(f.evidence)}</div>' if f.evidence else "")
            + f'<p class="rem"><b>Remediation:</b> {_esc(f.remediation)}</p></div>'
        )

    if report.skipped or report.suppressed:
        parts.append("<h2>Warnings &amp; notes</h2><ul>")
        for entry in report.skipped:
            parts.append(f"<li><code>{_esc(entry['file'])}</code> — {_esc(entry['reason'])}</li>")
        for sup in report.suppressed:
            parts.append(
                f"<li>suppressed by inline comment: {_esc(sup['rule_id'])} "
                f"({_esc(sup['kind'])}) at <code>{_esc(sup['file'])}:{sup['line']}</code></li>"
            )
        parts.append("</ul>")

    parts.append(
        "<footer><b>Methodology.</b> Portcullis statically parses pipeline "
        "definitions into a normalized model (triggers, permissions, jobs, "
        "steps) and evaluates platform-agnostic rules R1–R6 against it. "
        "Findings inside jobs reachable from untrusted triggers are escalated "
        "one severity level (marked ↑) — the same misconfiguration is more "
        "dangerous where attacker-controllable input can reach it. Pipeline "
        "files are never executed and no network access occurs at scan time."
        "<br><br><b>Limitations.</b><ul>"
        + "".join(f"<li>{_esc(li)}</li>" for li in _LIMITATIONS)
        + "</ul></footer></div></body></html>"
    )
    return "".join(parts) + "\n"
