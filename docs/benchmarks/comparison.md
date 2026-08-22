# Portcullis vs. the landscape

An honest positioning of Portcullis against existing research and tooling,
written July 2026. Prior art is acknowledged, not hidden: several excellent
tools cover parts of this space, and combining scanners is a legitimate
strategy — a 2026 comparative study of nine GitHub Actions scanners
([arXiv:2601.14455](https://arxiv.org/html/2601.14455v2)) explicitly found
that *no single scanner covers all identified weakness categories* and
recommended layering complementary tools.

## The research base

- **ARGUS** ([USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/muralee))
  introduced staged static taint analysis for GitHub workflows *and* the
  actions they call, evaluating 2.7M workflows and finding 4,307 injectable
  ones. It validates the core premise Portcullis is built on: untrusted
  context → shell sink is the dominant, findable pipeline vulnerability
  class. ARGUS goes deeper on GitHub (it analyzes action source code);
  Portcullis trades that depth for multi-platform breadth, determinism, and
  a CI-gate-shaped UX.
- **"Unpacking Security Scanners for GitHub Actions Workflows"**
  ([arXiv:2601.14455](https://arxiv.org/html/2601.14455v2)) identifies the
  weakness categories that matter (unpinned dependencies, excessive
  permissions, injection, secrets exposure, artifact integrity) — Portcullis
  rules R1–R6 map onto all five — and documents wild inconsistency between
  tools' false-positive philosophies (e.g., 125 vs. 3,620 artifact-integrity
  findings on the same corpus). Portcullis's answer to that problem is
  structural: confidence bands, hygiene-class demotion, and LOW-confidence
  findings capped at P3 so they surface without blocking.

## Tool-by-tool

| | Portcullis | [zizmor](https://docs.zizmor.sh/audits/) | [poutine](https://github.com/boostsecurityio/poutine) | actionlint | Checkov / KICS | OpenSSF Scorecard |
|---|---|---|---|---|---|---|
| Platforms | GitHub + GitLab + Jenkins | GitHub only | GitHub + GitLab | GitHub only | many IaC types, shallow CI rules | GitHub repo-level |
| Trigger-context severity escalation | **yes — first-class** | partial (persona levels) | partial | no | no | no |
| Taint source→sink for injection | yes (curated lists, honest confidence) | yes (template-injection) | yes | partial | no | no |
| Priority model + 0–100 score | **yes, deterministic + documented formula** | severity/persona | severity | n/a | severity | 0–10 aggregate |
| Outputs | JSON, HTML (self-contained), SARIF, Markdown | JSON, SARIF, GitHub annotations | JSON, SARIF | annotations | many | JSON |
| Merge gate (`--fail-on`) | yes | yes | yes | exit code | yes | no |
| Offline / no network | always | mostly (some online audits) | yes | yes | yes | needs API |
| Inline suppressions | yes (`# portcullis: ignore[R2]`) | yes | yes | yes | yes | n/a |
| Rule count | 6 rules / ~25 checks | 39 audits | ~a dozen rules | many (lint-focused) | thousands (IaC-wide) | ~20 checks |

## What Portcullis does that the others don't

1. **One normalized model across GitHub, GitLab, and Jenkins.** zizmor and
   actionlint are GitHub-only; poutine covers GitLab but not Jenkins. Every
   Portcullis rule runs unchanged on all three platforms because parsers
   normalize first — and adding CircleCI/Azure is a parser, not a rule
   rewrite.
2. **Context escalation as the ranking backbone.** The same `curl | bash` is
   P2 on a push trigger and escalates toward P0 inside a
   `pull_request_target` job. Other tools encode some of this per-rule;
   Portcullis applies it uniformly in the risk model, with a truth table in
   the test suite.
3. **Calibration as architecture, not tuning.** Confidence is a first-class
   field; LOW confidence hard-caps at P3; hygiene findings can't corroborate
   their way into P0; Jenkins findings are structurally capped at MEDIUM
   because a Groovy parse cannot honestly claim more.
4. **A self-contained HTML report** readable by a non-author, with the score
   formula printed next to the score and a limitations footer — plus a
   Markdown emitter sized for PR comments.

## What the others do that Portcullis doesn't (yet)

Stated plainly, per the no-overclaiming rule:

- **zizmor** has ~39 audits including online ones Portcullis deliberately
  omits (known-vulnerable actions, impostor commits, stale refs), cache
  poisoning heuristics, and auto-fix mode.
- **ARGUS** analyzes the *source of called actions* (JavaScript/composite),
  catching taint flows Portcullis's shallow `uses:` handling cannot see.
- **poutine** detects known-vulnerable third-party components via its
  database; Portcullis is offline-only by design and does not.
- **actionlint** is a full workflow-syntax linter (shellcheck integration,
  runner-label validation); Portcullis is not a linter and skips all of that.
- **Checkov/KICS** bring compliance-framework mappings (CIS, PCI-DSS).

These gaps are tracked in [VISION.md](../research-notes/roadmap.md)'s roadmap where they fit
Portcullis's offline-first thesis (deep reusable-workflow following, opt-in
online mode for known-compromised versions).

## Checks adopted from this review (July 2026)

The landscape review directly produced these additions, each credited to the
pattern's public documentation:

| New check | Prior art |
|---|---|
| R1 `credential-persistence` (checkout persists token on PR-driven workflows) | zizmor *artipacked* |
| R1 `artifact-poisoning` (artifact download under `workflow_run`) | documented artifact-poisoning attack class; zizmor/poutine |
| R2 `env-injection` (untrusted context → `$GITHUB_ENV`/`$GITHUB_OUTPUT`/`$GITHUB_PATH`) | zizmor *github-env* |
| R4 `secrets-inherit` (blanket secret forwarding to reusable workflows) | zizmor *secrets-inherit* |
| R6 `unsecure-commands` (`ACTIONS_ALLOW_UNSECURE_COMMANDS`) | zizmor *insecure-commands* |
| Inline `portcullis: ignore[...]` suppressions | standard across zizmor/poutine/actionlint |
| Markdown PR-comment output | zizmor/poutine GitHub integrations |

## Sources

- [zizmor audit rules documentation](https://docs.zizmor.sh/audits/)
- [ARGUS — USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/muralee) · [project site](https://secureci.org/argus)
- [Unpacking Security Scanners for GitHub Actions Workflows (arXiv:2601.14455)](https://arxiv.org/html/2601.14455v2)
- [poutine — BoostSecurity](https://github.com/boostsecurityio/poutine) · [announcement](https://org.boostsecurity.io/blog/unveiling-poutine-an-open-source-build-pipelines-security-scanner)
- [Grafana Labs on scanning at scale with zizmor](https://grafana.com/blog/how-to-detect-vulnerable-github-actions-at-scale-with-zizmor/)
