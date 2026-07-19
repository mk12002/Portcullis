## 🛡️ Portcullis — pipeline security report

**Score: 0/100** · P0: **6** · P1: **4** · P2: 0 · P3: 1 · files scanned: 2

<sub>target `D:/Code_stuff/Portcullis/tests/fixtures/github` · generated 2026-07-19T00:00:00+00:00 · portcullis v0.1.0 · score = max(0, 100 - 30*|P0| - 15*|P1| - 5*|P2| - 1*|P3|); INFO findings excluded</sub>

| Priority | Rule | Location | Job | Severity | Confidence | Untrusted | Finding |
|---|---|---|---|---|---|---|---|
| **P0** | R1 `pwn-request` | `.github/workflows/vulnerable.yml:21` | triage | CRITICAL ↑ | HIGH | ⚠️ yes | Job 'triage' runs on pull_request_target (secrets and a privileged token available) and checks out PR-head code — attacker-controlled code executes in a privileged context (pwn-request pattern). |
| **P0** | R2 `expression-injection` | `.github/workflows/vulnerable.yml:25` | triage | CRITICAL ↑ | HIGH | ⚠️ yes | Untrusted context 'github.event.pull_request.title' is interpolated directly into a run script in job 'triage'. Its value is expanded before the shell parses the line, so crafted input becomes part of the command. |
| **P0** | R3 `unpinned-third-party` | `.github/workflows/vulnerable.yml:29` | triage | CRITICAL ↑ | HIGH | ⚠️ yes | Third-party action 'example-org/super-linter' is pinned to a mutable reference (@v3). A compromised or retagged release changes what this pipeline executes. |
| **P0** | R5 `secret-echoed` | `.github/workflows/vulnerable.yml:27` | triage | CRITICAL ↑ | HIGH | ⚠️ yes | Secret(s) FIXTURE_FAKE_WEBHOOK_TOKEN are written to the job log by an echo/print in job 'triage'. Log masking is best-effort and fails on transformed values. |
| **P0** | R5 `secret-untrusted-context` | `.github/workflows/vulnerable.yml:27` | triage | HIGH ↑ | MEDIUM | ⚠️ yes | Job 'triage' uses repository secrets while reachable from an untrusted trigger (workflow triggered by pull_request_target). Combined with attacker-influenced execution this is the secret-exfiltration setup. |
| **P0** | R6 `curl-pipe-shell` | `.github/workflows/vulnerable.yml:31` | triage | HIGH ↑ | HIGH | ⚠️ yes | Step 'install tool (unverified remote install; inert example domain)' pipes a remote download directly into an interpreter — the pipeline executes whatever the remote host serves, unverified. |
| **P1** | R2 `expression-injection` | `.github/workflows/push-injection.yml:15` | build | HIGH | HIGH | no | Untrusted context 'github.event.head_commit' is interpolated directly into a run script in job 'build'. Its value is expanded before the shell parses the line, so crafted input becomes part of the command. |
| **P1** | R4 `write-all` | `.github/workflows/vulnerable.yml:15` | — | HIGH ↑ | HIGH | ⚠️ yes | permissions: write-all on workflow grants the token every scope (contents, packages, actions, id-token…) — far more than any single job needs. |
| **P1** | R3 `unpinned-first-party` | `.github/workflows/vulnerable.yml:39` | matrix-build | HIGH ↑ | HIGH | ⚠️ yes | First-party action 'actions/setup-python' is pinned to a mutable reference (@v5). A compromised or retagged release changes what this pipeline executes. |
| **P1** | R3 `unpinned-first-party` | `.github/workflows/vulnerable.yml:21` | triage | HIGH ↑ | HIGH | ⚠️ yes | First-party action 'actions/checkout' is pinned to a mutable reference (@v4). A compromised or retagged release changes what this pipeline executes. |
| **P3** | R1 `credential-persistence` | `.github/workflows/vulnerable.yml:21` | triage | LOW | MEDIUM | ⚠️ yes | actions/checkout in job 'triage' persists the repository token into .git config (the default) in a workflow reachable from PR-driven events — later steps and checked-out tooling can read it from disk. |

<details><summary><b>Remediations</b></summary>

- **R1 `pwn-request`** at `.github/workflows/vulnerable.yml:21` — Split the workflow: handle untrusted PR code under the unprivileged pull_request event, and keep pull_request_target jobs from checking out PR-head refs. If PR code must be processed, do it without secrets and with permissions: read-all or less.
- **R2 `expression-injection`** at `.github/workflows/vulnerable.yml:25` — Route the value through env: and reference it as a quoted shell variable, e.g. env: TITLE: ${{ <expr> }} then run: echo "$TITLE". The shell then receives the value as data, never as command text.
- **R3 `unpinned-third-party`** at `.github/workflows/vulnerable.yml:29` — Pin to a full commit SHA (uses: owner/action@<40-hex-sha> with a version comment) and update via a dependency bot; tags and branches are mutable.
- **R5 `secret-echoed`** at `.github/workflows/vulnerable.yml:27` — Never print secret expressions; pass secrets via env: to the consuming process and rely on masked, non-printed usage.
- **R5 `secret-untrusted-context`** at `.github/workflows/vulnerable.yml:27` — Move secret-using work to a workflow that runs only on trusted events, or gate it behind environment protection rules with required review.
- **R6 `curl-pipe-shell`** at `.github/workflows/vulnerable.yml:31` — Download to a file, verify a pinned checksum (sha256sum -c) or signature, then execute; or install from a pinned package.
- **R2 `expression-injection`** at `.github/workflows/push-injection.yml:15` — Route the value through env: and reference it as a quoted shell variable, e.g. env: TITLE: ${{ <expr> }} then run: echo "$TITLE". The shell then receives the value as data, never as command text.
- **R4 `write-all`** at `.github/workflows/vulnerable.yml:15` — Add an explicit least-privilege block, e.g. permissions: { contents: read } at the workflow top level, widening only the scopes a specific job needs.
- **R3 `unpinned-first-party`** at `.github/workflows/vulnerable.yml:39` — Pin to a full commit SHA (uses: owner/action@<40-hex-sha> with a version comment) and update via a dependency bot; tags and branches are mutable.
- **R3 `unpinned-first-party`** at `.github/workflows/vulnerable.yml:21` — Pin to a full commit SHA (uses: owner/action@<40-hex-sha> with a version comment) and update via a dependency bot; tags and branches are mutable.
- **R1 `credential-persistence`** at `.github/workflows/vulnerable.yml:21` — Add 'persist-credentials: false' to the checkout step unless a later step genuinely needs the persisted token.

</details>

<sub>↑ = severity escalated one level because the job is reachable from an untrusted trigger. Static analysis approximates reachability — see the project README for limitations.</sub>
