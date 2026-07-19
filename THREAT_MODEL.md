# Threat model — for Portcullis itself

A security tool is attack surface. This document states what Portcullis does
with the untrusted input it consumes and what it guarantees about its own
behavior.

## What Portcullis consumes

Pipeline definition files (`.github/workflows/*.yml`, `.gitlab-ci.yml`,
`Jenkinsfile`) from arbitrary repositories. These are **untrusted input**: a
scanned repository may be attacker-controlled.

## Guarantees

1. **Never executes pipeline content.** Files are parsed (ruamel.yaml for
   YAML; a regex/structural scanner for Groovy). No `eval`, no subprocess of
   scanned content, no Groovy runtime. The Jenkins parser deliberately trades
   fidelity for safety — Groovy cannot be evaluated safely, so it never is.
2. **No network access at scan time.** No resolving action tags against a
   registry, no fetching called workflows, no telemetry. `pip install` is the
   only network-touching operation, and it happens before any scan.
3. **Malformed input degrades, never escalates.** Any parse failure —
   malformed YAML, non-UTF-8 bytes, empty files, absurd nesting — becomes a
   warning plus a LOW R0 finding. One bad file never aborts a scan (tested in
   `tests/test_edge_cases.py`).
4. **Detected secrets are redacted.** When R5 flags a plaintext
   credential-shaped value, the value never appears in any output format —
   evidence strings carry only length and entropy metadata. Redaction is
   explicitly tested against all three emitters.
5. **Deterministic output.** Same input tree → byte-identical
   JSON/HTML/SARIF/Markdown (the single top-level timestamp excepted), so
   reports are diffable and a tampered rerun is detectable.
6. **Suppressions are never silent.** Inline `portcullis: ignore` comments
   drop a finding from the findings list but are themselves reported (file,
   line, rule) in every output format — an attacker quietly suppressing a
   finding leaves a visible trace.

## Residual risks

- **YAML parser attack surface.** ruamel.yaml processes hostile input; it is
  the project's one runtime dependency, version-bounded in `pyproject.toml`.
  YAML bombs (deep anchors/aliases) can consume memory; scans should run with
  CI-level resource limits like any other build step.
- **Report is derived from hostile input.** Evidence strings originate in
  scanned files; the HTML emitter escapes all interpolated content to prevent
  markup injection into the report itself.
- **Findings are advice.** Portcullis output gates merges; a wrong LOW/clean
  verdict is possible (see Limitations in README). It is one layer, not an
  authorization system.

## Fixture policy

The repository's own test fixtures are deliberately vulnerable but inert:
echo-only payloads, `example.com` URLs, fake-marked secret-shaped strings.
An automated guard (`tests/test_inertness.py`) fails the build if a fixture
ever contains a functional exploit shape, a real-looking credential, or a
non-inert URL.
