"""Use Portcullis as a Python library.

Scans a directory programmatically and prints the findings, then shows how to
get each report format. Run:

    python examples/python_api.py examples/vulnerable-repo
"""

from __future__ import annotations

import sys
from pathlib import Path

from portcullis.core.engine import scan
from portcullis.core.models import ScanConfig
from portcullis.emitters import emit_json, emit_markdown, emit_sarif


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".")

    # Configure the scan (all fields optional).
    config = ScanConfig(
        platforms=frozenset({"github", "gitlab", "jenkins"}),
        trusted_action_prefixes=(),  # e.g. ("myorg/",) to treat your org as first-party
    )

    report = scan(target, config)

    print(f"Scanned {len(report.files_scanned)} pipeline file(s) in {target}")
    print(f"Score: {report.score}/100 · priorities: {report.priority_counts}\n")

    for f in report.findings:
        sev = (f.severity or f.base_severity).name
        pr = f.priority.name if f.priority is not None else "-"
        mark = " (escalated)" if f.escalated else ""  # ASCII-only for portability
        print(f"[{pr}/{sev}{mark}] {f.rule_id} {f.kind}")
        print(f"    {f.file_path}:{f.line}  (confidence: {f.confidence.name})")
        print(f"    {f.message}")
        print(f"    fix: {f.remediation}\n")

    # Every report format is one function call on the same Report object:
    _json_text = emit_json(report)  # canonical machine format
    _sarif_text = emit_sarif(report)  # SARIF 2.1.0 for code scanning
    _md_text = emit_markdown(report)  # PR-comment-sized Markdown

    # Exit non-zero if any P0/P1 finding exists — a simple gate.
    blocking = [f for f in report.findings if f.priority is not None and f.priority.value <= 1]
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
