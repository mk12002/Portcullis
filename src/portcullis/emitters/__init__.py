"""Output emitters: canonical JSON, self-contained HTML, SARIF 2.1.0, Markdown."""

from portcullis.emitters.html_emitter import emit_html
from portcullis.emitters.json_emitter import emit_json
from portcullis.emitters.md_emitter import emit_markdown
from portcullis.emitters.sarif_emitter import emit_sarif

EMITTERS = {"json": emit_json, "html": emit_html, "sarif": emit_sarif, "md": emit_markdown}

__all__ = ["EMITTERS", "emit_json", "emit_html", "emit_sarif", "emit_markdown"]
