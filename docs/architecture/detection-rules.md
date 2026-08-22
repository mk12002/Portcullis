# Detection Rules

Portcullis ships six rule families (R1–R6) plus a synthetic R0 for unparseable
files. Run `portcullis rules list` for the live catalog with false-positive
notes. Each rule operates on the normalized model, so it applies to every
platform that can express the relevant construct.

## R0 — Unparseable pipeline file

A file that could not be parsed becomes a LOW finding rather than a crash — a
malformed workflow may silently not run and hides from analysis.

## R1 — Dangerous triggers

Privileged workflows processing attacker-controllable input.

| kind | detects |
|---|---|
| `pwn-request` | `pull_request_target`/`workflow_run` + checkout of PR-head code |
| `dangerous-trigger` | privileged untrusted trigger without a detected checkout |
| `artifact-poisoning` | artifact download in a `workflow_run` job |
| `credential-persistence` | checkout without `persist-credentials: false` on a PR-reachable workflow |
| `self-hosted-pr` | self-hosted runner reachable from PR events |
| `mr-untrusted-context` | GitLab MR job + credential-looking variables |
| `pr-context-credentials` | Jenkins `credentials()` + `CHANGE_*` context |

*FP note:* `pull_request_target` is legitimate for labeling/triage that never
touches PR code — reachability to a checkout is what escalates.

## R2 — Expression injection

Attacker-controllable context interpolated into a shell/script line.

| kind | platform |
|---|---|
| `expression-injection` | GitHub (`${{ }}` in `run:`) |
| `env-injection` | GitHub (untrusted value into `$GITHUB_ENV`/`OUTPUT`/`PATH`) |
| `script-injection` | GitHub (`actions/github-script` body) |
| `variable-injection` | GitLab (unquoted MR variable in `script:`) |
| `groovy-interpolation` | Jenkins (double-quoted `sh` with `CHANGE_*`/`params.*`) |

*FP note:* interpolating trusted context (`github.sha`, `matrix.*`) is safe; the
fix is routing the value through `env:` and quoting it.

## R3 — Action / image pinning

| kind | severity |
|---|---|
| `unpinned-third-party` | HIGH |
| `unpinned-first-party` | MEDIUM (hygiene) |
| `image-mutable-latest` | MEDIUM (hygiene) |
| `image-pinned-tag` | LOW (hygiene) |

*FP note:* SHA pinning has an update-burden tradeoff — pair it with a dependency
bot. `--trusted-actions PREFIX` reclassifies your org as first-party.

## R4 — Token permissions

`missing-permissions`, `write-all`, `broad-write` (≥3 write scopes),
`secrets-inherit` (blanket `secrets: inherit`). All escalate in
untrusted-reachable jobs. GitHub-only (guarded by the `permissions` capability).

*FP note:* some jobs legitimately need `contents: write`.

## R5 — Secret exposure

`secret-echoed`, `secret-cli-arg`, `secret-untrusted-context`,
`plaintext-secret` (hardcoded high-entropy value — **always redacted** in output).

*FP note:* entropy detection also matches hashes/IDs — those are LOW confidence,
and a non-secret-key denylist (`name`, `platforms`, URLs, refs) excludes common
false positives.

## R6 — Step integrity

`curl-pipe-shell` (`curl … | bash`; HIGH over plaintext HTTP), `unverified-download`
(download without a visible checksum; LOW), `unsecure-commands`
(`ACTIONS_ALLOW_UNSECURE_COMMANDS`).

*FP note:* these patterns are common in legitimate setup scripts — the
remediation is checksum verification, not removal.

## How rules combine

Rules are independent single-responsibility detectors. The **risk model** reads
their co-occurrence: an R1 `pwn-request` becomes CRITICAL when R2 or R5 also fires
on the same job (the exfiltration kill chain), and two distinct substantive
findings on one job corroborate up a priority level — but only reach the
merge-blocking `P0` when the job is attacker-reachable. See
[Architecture](architecture.md).
