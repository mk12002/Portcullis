# Changelog

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
actionlint, and the ARGUS paper — see docs/COMPARISON.md.)

### Interface
- `portcullis scan` with `--format json|html|sarif|md|all`, `--out`,
  `--fail-on P0..P3` exit-code gate, `--platforms`, `--trusted-actions`,
  `--quiet`; `portcullis rules list`; `portcullis version`.
- Inline suppressions: `# portcullis: ignore` / `# portcullis: ignore[R2,R5]`
  (trailing or line-above; `//` for Jenkinsfiles), reported in every output.
- Deterministic output in all four formats (timestamp excepted).

### Calibration (from a real-world evaluation — see docs/EVALUATION.md)
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

### Safety & quality
- 150+ tests: risk truth table, taint cases, determinism-under-shuffle,
  per-platform known-answer fixtures, emitter byte-determinism, secret
  redaction (verified on real data: 0 leaks), CLI exit codes, edge cases,
  automated inertness guard, and a dogfood test asserting Portcullis's own CI
  passes its own scan at 100/100.
- Threat model, honest limitations, Apache-2.0.
