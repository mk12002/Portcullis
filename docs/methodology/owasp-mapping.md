# Portcullis ↔ OWASP Top 10 CI/CD Security Risks

Portcullis's detection rules map directly onto the **[OWASP Top 10 CI/CD
Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)**
(Krivelevich & Gil, 2022) — the industry-standard taxonomy for pipeline
security. This is Portcullis's natural framework fit: it is a CI/CD security
tool, so it speaks the CI/CD Top-10 language rather than, say, the LLM/GenAI
lists that target a different problem domain.

Each Portcullis finding `kind` is listed under the OWASP risk it evidences. A
single rule can touch more than one risk.

| OWASP CI/CD risk | What it means | Portcullis rules / kinds |
|---|---|---|
| **CICD-SEC-1** — Insufficient Flow Control | changes reach sensitive stages without adequate review/gating | *(partial)* Portcullis is a **gate mechanism** for this risk via `--fail-on`; it detects the config that makes flow control matter, and its own CI is the reference gate |
| **CICD-SEC-2** — Inadequate Identity & Access Mgmt | over-permissioned identities/tokens | R4 `missing-permissions`, `write-all`, `broad-write` |
| **CICD-SEC-3** — Dependency Chain Abuse | pulling in code you don't control / can't verify | R3 `unpinned-third-party`, `unpinned-first-party`; R6 `curl-pipe-shell`, `unverified-download` |
| **CICD-SEC-4** — Poisoned Pipeline Execution (PPE) | attacker-controlled code runs in the pipeline | R1 `pwn-request`, `dangerous-trigger`, `self-hosted-pr`; **R2 all injection kinds** (`expression-injection`, `env-injection`, `script-injection`, `variable-injection`, `groovy-interpolation`) |
| **CICD-SEC-5** — Insufficient Pipeline-Based Access Controls | a compromised step can do more than it should | R4 (scope of the job token); the **trigger-context escalation** model is a direct expression of PBAC thinking |
| **CICD-SEC-6** — Insufficient Credential Hygiene | secrets exposed, over-shared, or long-lived | R5 `secret-echoed`, `secret-cli-arg`, `secret-untrusted-context`, `plaintext-secret`; R4 `secrets-inherit`; R1 `credential-persistence` |
| **CICD-SEC-7** — Insecure System Configuration | dangerous platform settings enabled | R6 `unsecure-commands` (`ACTIONS_ALLOW_UNSECURE_COMMANDS`) |
| **CICD-SEC-8** — Ungoverned Usage of 3rd-Party Services | unvetted external actions/services | R3 third-party pinning (the `--trusted-actions` allowlist is the governance knob) |
| **CICD-SEC-9** — Improper Artifact Integrity Validation | trusting artifacts/downloads that could be tampered | R1 `artifact-poisoning`; R6 `curl-pipe-shell`, `unverified-download`; R3 image digest pinning |
| **CICD-SEC-10** — Insufficient Logging & Visibility | can't see what the pipeline did | *(out of scope for a static scanner — Portcullis analyzes config, not runtime logs; noted honestly)* |

## Coverage summary

Portcullis provides **detection coverage for 8 of the 10** OWASP CI/CD risks
(SEC-2 through SEC-9), acts as an enforcement **mechanism** for SEC-1 (flow
control via the merge gate), and honestly does **not** cover SEC-10 (runtime
logging/visibility), which is a runtime-observability concern outside a static
scanner's remit.

## Why this mapping matters

- **For adopters:** it lets a security team place Portcullis in a framework they
  already use for CI/CD risk, and shows exactly which risks it does and does not
  address — no overclaiming.
- **For contribution:** the OWASP CI/CD project welcomes methodology and analysis
  contributions; this mapping (plus Portcullis's real-world evaluation and the
  trigger-context reachability model) is the kind of practical, tool-backed
  material that fits an OWASP methodology or research contribution.

> **Honesty note.** This maps Portcullis onto a published OWASP taxonomy; it does
> not claim endorsement by or affiliation with OWASP. The CICD-SEC identifiers
> and definitions are OWASP's; the rule mapping is ours.
