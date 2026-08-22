"""Smoke tests for the Hugging Face / Gradio demo core (demo/app.py).

Only the pure `scan_pipeline_text` function is tested; the Gradio UI wiring
imports gradio lazily inside `_build_ui`, so these run without gradio installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

DEMO_DIR = Path(__file__).parent.parent / "demo"
if str(DEMO_DIR) not in sys.path:
    sys.path.insert(0, str(DEMO_DIR))

app = pytest.importorskip("app")  # demo/app.py


def test_vulnerable_example_scores_zero():
    summary, report_html = app.scan_pipeline_text(app.EXAMPLE, "auto")
    assert summary["platform"] == "GitHub Actions"
    assert summary["score"] == 0 and summary["findings"] > 0
    # the rendered report is the hardened HTML (escaped + CSP)
    assert "Content-Security-Policy" in report_html


def test_clean_snippet_scores_100():
    clean = (
        "on: push\npermissions: {contents: read}\njobs:\n  a:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
    )
    summary, _ = app.scan_pipeline_text(clean, "auto")
    assert summary["score"] == 100 and summary["findings"] == 0


@pytest.mark.parametrize(
    "text,expected",
    [
        ("on: push\njobs: {}\n", "GitHub Actions"),
        ("stages: [test]\nbuild:\n  script:\n    - echo hi\n", "GitLab CI"),
        ("pipeline {\n  stages { stage('x') { steps { sh 'echo' } } }\n}\n", "Jenkins"),
    ],
)
def test_platform_autodetect(text, expected):
    assert app._detect_platform(text) == expected


def test_markdown_render_has_table_when_findings():
    summary, _ = app.scan_pipeline_text(app.EXAMPLE, "auto")
    md = app._render_markdown(summary)
    assert "Score:" in md and "| Priority |" in md
