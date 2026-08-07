# Contributing to Portcullis

## Setup

```bash
pip install -e ".[dev]"
python -m pytest          # full suite
python -m ruff check .    # lint
python -m mypy src/portcullis # types
```

All three must be green before a PR.

## Adding a platform

1. Create `portcullis/platforms/<name>.py` subclassing `platforms.base.Platform`:
   - `matches(rel_path)` — is this repo-relative POSIX path a pipeline file of yours?
   - `parse(text, rel_path) -> Pipeline` — emit the **normalized model** (`core/models.py`): triggers with `untrusted_privileged`/`untrusted_input` classification, jobs with `reachable_from_untrusted` computed at parse time, steps with `run`/`uses`/`env` and accurate line numbers.
2. Register it in `platforms/__init__.py` and add its name to `cli.VALID_PLATFORMS`.
3. Ship an **inert-but-vulnerable fixture** plus a clean fixture, and a test asserting exact rule firings.
4. If your parse is structural rather than faithful (like Jenkins/Groovy), set `fidelity="best-effort"` — rules then cap confidence at MEDIUM automatically. Document the reduced fidelity; never overclaim.

Because rules run against the normalized model, a new platform gets all six rules for free.

## Adding a rule

1. Create `portcullis/rules/<name>.py` with:
   - `RULES: list[RuleMeta]` — id, name, summary, and an honest **false-positive note** (mandatory; it ships in `rules list` and SARIF help).
   - `check(pipeline: Pipeline, config: ScanConfig) -> list[Finding]` — operate on the normalized model only; platform-specific syntax belongs in parsers.
2. Register the module in `rules/__init__.py::ALL_RULE_MODULES`.
3. Choose `base_severity` and `confidence` honestly. If the finding's danger already encodes trigger context (like R1), set `escalatable=False` so it isn't double-escalated.
4. Add truth-table rows to `tests/test_risk.py` if the rule introduces new priority interactions, and fixture assertions for each platform it fires on.
5. **Every `kind` your rule can emit must have an explicit test.** Run
   `pytest --cov=portcullis --cov-report=term-missing` and confirm your new
   branches are covered — a coverage pass is how we find "implemented but
   untested" behaviors (see `tests/test_rule_coverage_gaps.py`).
6. If you touch the SARIF emitter, `tests/test_sarif_schema.py` re-validates the
   output against the official SARIF 2.1.0 schema — keep it green. Install dev
   deps with `pip install -e ".[dev]"` (pulls in `jsonschema`, dev-only).

## The inert-fixture law (hard rule)

Fixtures must be **vulnerable-looking, harmless-acting**:

- Payloads are inert `echo` statements — never a working exploit, exfiltration step, or reverse shell, not even commented out.
- Secret-shaped strings must be obviously fake (contain `fake`/`fixture`/`0000`).
- URLs use reserved documentation domains (`example.com`) only.
- Every vulnerable fixture carries the `INERT-BUT-VULNERABLE FIXTURE` header.

`tests/test_inertness.py` enforces all of this automatically. A PR that weakens the guard or violates it will not be merged. Likewise: no fabricated CVEs, incident names, or accusations against real repositories anywhere in code, fixtures, or docs.

## Calibration over noise

Pipeline scanners that flood PRs with false HIGHs get disabled. When in doubt, lower the confidence, not the bar: LOW-confidence findings surface at P3 without blocking. Every rule's FP note should tell a reviewer exactly when the finding is safe to dismiss.
