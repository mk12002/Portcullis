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

## Denial-of-service hardening (parser)

Because pipeline files come from untrusted repositories, the parser is
hardened against a malicious file trying to hang or exhaust a scan — important
when Portcullis runs as a CI gate on pull-request content:

- **YAML alias bombs ("billion laughs").** ruamel's round-trip loader keeps
  aliases as shared references, so a bomb parses instantly but explodes when
  traversed (e.g. `str()` on an env value). After loading, any alias-bearing
  document is walked with a hard node budget (`MAX_YAML_NODES`, 2,000,000) that
  short-circuits, so a bomb is refused in bounded time (~0.6 s) regardless of
  its nominal expansion (10⁸–10¹³ nodes), while legitimate anchor reuse —
  dozens of jobs sharing a `<<: *default` merge — is unaffected. Regression:
  `tests/test_security.py`.
- **Oversized files.** Files larger than `MAX_FILE_BYTES` (2 MB — orders of
  magnitude above any real pipeline file) are skipped with a LOW finding rather
  than read into memory, bounding parse time, regex work, and memory.
- **Deep nesting.** ruamel raises on excessive recursion; the engine catches it
  and degrades the file to a LOW finding instead of crashing.
- **Regex safety.** Detection patterns avoid nested quantifiers; worst-case
  behavior is linear-to-quadratic in a single line's length, which the file
  size cap bounds — no catastrophic (exponential) backtracking.

## Confidentiality & integrity of the scan

- **Symlinks are not followed.** A pipeline file that is a symlink is skipped,
  not read — a malicious repo cannot use `.gitlab-ci.yml → /etc/passwd` to make
  Portcullis read an arbitrary host file into its report. `os.walk` does not
  descend into symlinked directories either. Regression: `tests/test_security.py`.
- **Report is derived from hostile input, but inert.** Evidence strings
  originate in scanned files. The HTML emitter escapes *all* interpolated
  content (`html.escape(quote=True)`), and — as defense-in-depth — the report
  carries a strict `Content-Security-Policy` (`default-src 'none'; style-src
  'unsafe-inline'`) so no script can execute and no network request can be made
  even if an escaping bug ever slipped through. The report is fully
  self-contained, so the CSP never affects rendering. Regression:
  `tests/test_security.py`.

## Residual risks

- **YAML parser attack surface.** ruamel.yaml still processes hostile input; it
  is the project's one runtime dependency, version-bounded in `pyproject.toml`,
  and chosen over unsafe loaders (no `!!python/object` construction — the
  round-trip loader rejects arbitrary tags, so YAML cannot execute code). The
  node-budget and size caps above bound its resource use.
- **Findings are advice.** Portcullis output gates merges; a wrong LOW/clean
  verdict is possible (see Limitations in README). It is one layer, not an
  authorization system.
- **Markdown output is for trusted renderers.** The Markdown emitter escapes
  table-breaking characters; it is intended for GitHub/GitLab PR comments,
  which sanitize HTML. Do not render Portcullis Markdown through a non-
  sanitizing HTML renderer on untrusted input — use the HTML report (CSP-
  protected) for that.

## Fixture policy

The repository's own test fixtures are deliberately vulnerable but inert:
echo-only payloads, `example.com` URLs, fake-marked secret-shaped strings.
An automated guard (`tests/test_inertness.py`) fails the build if a fixture
ever contains a functional exploit shape, a real-looking credential, or a
non-inert URL.
