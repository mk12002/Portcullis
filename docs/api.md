# Python API

Portcullis is usable as a library, not just a CLI. The package ships type hints
(`py.typed`), so your editor and `mypy` see the full API.

## Scan a path

```python
from pathlib import Path
from portcullis.core.engine import scan
from portcullis.core.models import ScanConfig

config = ScanConfig(
    platforms=frozenset({"github", "gitlab", "jenkins"}),
    trusted_action_prefixes=("myorg/",),   # optional
)
report = scan(Path("."), config)

print(report.score, report.priority_counts)
for f in report.findings:
    sev = (f.severity or f.base_severity).name
    print(f.rule_id, f.kind, f"{f.file_path}:{f.line}", sev, f.confidence.name)
```

## Render any format

Every emitter is a pure function of the `Report`:

```python
from portcullis.emitters import emit_json, emit_html, emit_sarif, emit_markdown

json_text  = emit_json(report)      # canonical, deterministic
html_text  = emit_html(report)      # self-contained, CSP-hardened
sarif_text = emit_sarif(report)     # SARIF 2.1.0 (schema-validated)
md_text    = emit_markdown(report)  # PR-comment sized
```

## Key types

- `portcullis.core.models.Report` — the scan result (`findings`, `score`,
  `priority_counts`, `files_scanned`, `skipped`, `suppressed`).
- `portcullis.core.models.Finding` — one traceable finding (`rule_id`, `kind`,
  `file_path`, `line`, `base_severity`, `severity`, `escalated`, `confidence`,
  `priority`, `message`, `remediation`, `evidence`).
- `portcullis.core.models.ScanConfig` — scan options.
- Enums: `Severity`, `Confidence`, `Priority` (all `IntEnum`; note **`Priority.P0 == 0`**
  is falsy — always compare `priority is not None`).

A complete, runnable script is at [`examples/python_api.py`](examples.md).

## Determinism & safety

The API inherits the tool's guarantees: it never executes pipeline content,
performs no network access, and returns deterministic results (the `now`
parameter to `scan()` lets you pin the timestamp for reproducible output in
tests).
