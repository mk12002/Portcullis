# Changelog

## Unreleased — packaging & product hardening

Turned the project into a production-shaped, installable Python package.

### Packaging
- **`src/` layout** (`src/portcullis/`) — the standard package layout that
  prevents accidental imports of the working tree instead of the installed
  package. `pip install .` / `pip install -e .` unchanged for users.
- Ships **type information** (`py.typed`, PEP 561) so downstream `mypy` sees the
  API. Verified `python -m build` produces a valid sdist + wheel that pass
  `twine check`, and a clean-venv wheel install exposes the `portcullis` command
  with **only `ruamel.yaml`** as a runtime dependency.
- Added `requirements.txt` / `requirements-dev.txt` (mirroring pyproject),
  richer `[project.urls]`, and a `docs` extra (`mkdocs-material`).

### Observability
- **Logging** (`portcullis.logging_config`): stderr, silent by default,
  `-v`/`-vv` for INFO/DEBUG. As a library it never configures the host app's
  logging. Console summary made ASCII-safe for legacy Windows terminals.

### Project scaffolding
- `examples/` — runnable example repos (vulnerable + clean), a Python-API
  script, and a copy-paste CI-gate workflow.
- **MkDocs Material** documentation site (`mkdocs.yml` + `docs/*.md`), buildable
  and deployable to GitHub Pages via a workflow.
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff`, GitHub issue/PR templates,
  Dependabot (pip + actions), and CI/CodeQL/release/docs workflows — all
  SHA-pinned and least-privilege, so they pass Portcullis's own dogfood scan.
- `docs/BENCHMARKS` — measured throughput (~360 files/s synthetic; 66 real files
  in ~1.4 s, zero crashes).

## 0.1.0 — 2026-07-19

Initial release.

### Core
- Normalized pipeline model shared by all platform parsers; rules written once.
- Risk model: trigger-context escalation (+1 severity in untrusted-reachable
  jobs), deterministic P0–P3 priority (severity × confidence ×
  corroboration), transparent 0–100 score.
- Lightweight taint analysis: curated untrusted-source lists per platform,
  run-sink vs. env-routed distinction.

### Platforms
- GitHub Actions (full fidelity): triggers, permissions, matrix, reusable
  workflows (shallow), container/service images.
- GitLab CI: rules/only → MR-trigger mapping, variables, images.
- Jenkins (best-effort structural Groovy parse, confidence capped at MEDIUM).

### Rules (6 rules, ~25 checks)
- R1 dangerous triggers: pwn-request, dangerous-trigger, self-hosted-pr,
  mr-untrusted-context, pr-context-credentials, **artifact-poisoning**,
  **credential-persistence**.
- R2 expression injection: expression-injection, script-injection
  (github-script), **env-injection** (`$GITHUB_ENV`/`$GITHUB_OUTPUT`/
  `$GITHUB_PATH`), variable-injection (GitLab), groovy-interpolation
  (Jenkins).
- R3 pinning: unpinned-third-party, unpinned-first-party,
  image-mutable-latest, image-pinned-tag.
- R4 permissions: missing-permissions, write-all, broad-write,
  **secrets-inherit**.
- R5 secret exposure: secret-echoed, secret-cli-arg, secret-untrusted-context,
  plaintext-secret (redacted everywhere).
- R6 step integrity: curl-pipe-shell, unverified-download,
  **unsecure-commands**.
- R0 parse errors surface as LOW findings; malformed input never crashes a scan.

(Bolded checks were added after a landscape review against zizmor, poutine,
actionlint, and the ARGUS paper — see docs/benchmarks/comparison.md.)

### Interface
- `portcullis scan` with `--format json|html|sarif|md|all`, `--out`,
  `--fail-on P0..P3` exit-code gate, `--platforms`, `--trusted-actions`,
  `--quiet`; `portcullis rules list`; `portcullis version`.
- Inline suppressions: `# portcullis: ignore` / `# portcullis: ignore[R2,R5]`
  (trailing or line-above; `//` for Jenkinsfiles), reported in every output.
- Deterministic output in all four formats (timestamp excepted).

### Calibration (from a real-world evaluation — see docs/benchmarks/evaluation.md)
Running against 66 pipeline files from 10 well-known OSS projects (flask,
fastapi, requests, actions/runner, gitlab-runner, jenkinsci/pipeline-examples,
…) surfaced two calibration bugs, both fixed with regression tests:
- **Corroboration no longer over-escalates to P0.** Hygiene findings (e.g.
  tag-pinned `docker/*` actions + broad-write) on a *trusted-trigger* job now
  floor at P1; P0 is reserved for attacker-reachable criticals. Cut spurious
  P0s on the dataset from 9 to 3.
- **Plaintext-secret precision.** A non-secret-key denylist (job/artifact
  `name`, `platforms`, URLs, refs…) plus rejection of path/list/URL-shaped
  values eliminated 9 false positives with no loss of genuine detections.
- Verified head-to-head vs zizmor 1.27.0: directional agreement on repo health,
  and Portcullis scanned the GitLab/Jenkins files zizmor cannot.

### Security hardening (the parser processes untrusted repos)
A self-security-review found and fixed a real denial-of-service, plus added
defense-in-depth. All covered by `tests/test_security.py`:
- **YAML alias-bomb ("billion laughs") DoS — FIXED.** A 514-byte file with an
  alias bomb under `env:` made the rules phase run ~6 s (10⁷ nodes); two more
  levels would hang ~10 min. A bounded node-budget walk now refuses such files
  in ~0.6 s while leaving legitimate anchor reuse untouched.
- **Oversized-file and deep-nesting resource exhaustion — bounded.** 2 MB file
  cap; deep recursion degrades to a LOW finding, never a crash.
- **Symlink traversal — blocked.** Symlinked pipeline files are skipped, so a
  malicious repo can't read arbitrary host files into the report.
- **HTML report XSS — hardened.** All evidence was already HTML-escaped; added a
  strict `Content-Security-Policy` (`default-src 'none'`) so the self-contained
  report can never execute script or make a network request.
- Confirmed clean: no `eval`/`exec`/`subprocess`/`pickle`/unsafe-YAML sinks; the
  round-trip loader cannot construct arbitrary Python objects.

### Safety & quality
- 175 tests, 95% coverage: risk truth table, taint cases,
  determinism-under-shuffle, per-platform known-answer fixtures, emitter
  byte-determinism, secret redaction (verified on real data: 0 leaks), CLI exit
  codes, edge cases, automated inertness guard, and a dogfood test asserting
  Portcullis's own CI passes its own scan at 100/100. Every rule `kind` the
  engine can emit has an explicit test.
- **SARIF output is validated against the official SARIF 2.1.0 JSON schema** in
  the test suite (`tests/test_sarif_schema.py`, schema vendored at
  `tests/schema/`); the inert fixtures additionally validate against the real
  GitHub Actions and GitLab CI schemas. `jsonschema` is a dev-only dependency —
  the tool's runtime still has the single dependency `ruamel.yaml`.
- Threat model, honest limitations, Apache-2.0.
