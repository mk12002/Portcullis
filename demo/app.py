"""Portcullis — "Try it in your browser" demo (Gradio / Hugging Face Space).

Paste a CI/CD pipeline definition, pick the platform (or let it auto-detect),
and get Portcullis's findings, score, and the self-contained HTML report — the
exact same engine the CLI uses, running fully offline and statically.

Deploy: create a Hugging Face Space (SDK: Gradio) and push this folder. HF runs
`app.py`. See demo/README.md for the Space metadata header.
"""

from __future__ import annotations

import html as _html
import tempfile
from pathlib import Path

from portcullis import __version__
from portcullis.core.engine import scan
from portcullis.core.models import ScanConfig
from portcullis.emitters import emit_html

# Where to write the pasted text so the engine's file-discovery matches it.
PLATFORM_PATHS = {
    "GitHub Actions": ".github/workflows/pasted.yml",
    "GitLab CI": ".gitlab-ci.yml",
    "Jenkins": "Jenkinsfile",
}

EXAMPLE = """# An inert-but-vulnerable example (paste your own instead)
on: pull_request_target
permissions: write-all
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "Thanks for PR ${{ github.event.pull_request.title }}"
      - uses: example-org/pr-linter@v1
"""


def _detect_platform(text: str) -> str:
    """Best-effort platform guess from the pasted content."""
    lowered = text.lower()
    if "pipeline {" in text or "\nnode" in text or "stage(" in text:
        return "Jenkins"
    if "stages:" in lowered or "\nscript:" in lowered or ".gitlab" in lowered:
        return "GitLab CI"
    return "GitHub Actions"


def scan_pipeline_text(text: str, platform: str = "auto") -> tuple[dict, str]:
    """Scan a single pasted pipeline document. Returns (summary dict, html report).

    Pure and testable — the Gradio UI is a thin wrapper around this.
    """
    text = text or ""
    if platform in ("auto", "", None):
        platform = _detect_platform(text)
    rel = PLATFORM_PATHS.get(platform, PLATFORM_PATHS["GitHub Actions"])

    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        report = scan(Path(d), ScanConfig())

    summary = {
        "platform": platform,
        "score": report.score,
        "priority_counts": report.priority_counts,
        "findings": len(report.findings),
        "rows": [
            {
                "priority": f.priority.name if f.priority is not None else "-",
                "severity": (f.severity or f.base_severity).name,
                "confidence": f.confidence.name,
                "rule": f"{f.rule_id} {f.kind}",
                "line": f.line,
                "message": f.message,
                "remediation": f.remediation,
            }
            for f in report.findings
        ],
    }
    return summary, emit_html(report)


def _render_markdown(summary: dict) -> str:
    counts = summary["priority_counts"]
    head = (
        f"### Score: {summary['score']}/100  \n"
        f"**platform:** {summary['platform']} · "
        f"P0: **{counts['P0']}** · P1: **{counts['P1']}** · "
        f"P2: {counts['P2']} · P3: {counts['P3']} · "
        f"findings: {summary['findings']}\n\n"
    )
    if not summary["rows"]:
        return head + "✅ No findings — this pipeline matched no detection rule."
    rows = ["| Priority | Rule | Line | Sev | Conf | Finding |", "|---|---|---|---|---|---|"]
    for r in summary["rows"]:
        msg = r["message"].replace("|", "\\|")
        rows.append(
            f"| **{r['priority']}** | {r['rule']} | {r['line']} | "
            f"{r['severity']} | {r['confidence']} | {msg} |"
        )
    return head + "\n".join(rows)


def _build_ui():  # pragma: no cover - UI wiring, exercised by launching the app
    import gradio as gr

    def run(text, platform):
        summary, report_html = scan_pipeline_text(text, platform)
        # sandbox the untrusted report HTML inside an iframe (defense-in-depth)
        srcdoc = _html.escape(report_html, quote=True)
        iframe = (
            f'<iframe sandbox="allow-same-origin" style="width:100%;height:520px;'
            f'border:1px solid #ccc;border-radius:8px" srcdoc="{srcdoc}"></iframe>'
        )
        return _render_markdown(summary), iframe

    with gr.Blocks(title="Portcullis — CI/CD pipeline security scanner") as demo:
        gr.Markdown(
            f"# 🏰 Portcullis\n"
            f"Static security scanner for CI/CD pipelines (GitHub Actions · GitLab CI · "
            f"Jenkins). Paste a pipeline, get prioritized findings. Runs offline; never "
            f"executes your pipeline. `v{__version__}`"
        )
        with gr.Row():
            with gr.Column(scale=1):
                inp = gr.Code(value=EXAMPLE, language="yaml", label="Pipeline definition")
                plat = gr.Dropdown(
                    ["auto", "GitHub Actions", "GitLab CI", "Jenkins"],
                    value="auto",
                    label="Platform",
                )
                btn = gr.Button("Scan", variant="primary")
            with gr.Column(scale=1):
                out_md = gr.Markdown(label="Findings")
        out_html = gr.HTML(label="Full report")
        btn.click(run, inputs=[inp, plat], outputs=[out_md, out_html])
        gr.Markdown(
            "Source & docs: [github.com/mk12002/Portcullis](https://github.com/mk12002/Portcullis)"
        )
    return demo


if __name__ == "__main__":  # pragma: no cover
    _build_ui().launch()
