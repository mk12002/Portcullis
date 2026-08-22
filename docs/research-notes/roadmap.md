# Vision

**Portcullis is a pipeline-security gate**: a static analyzer that catches the
CI/CD misconfigurations behind real pipeline compromises — untrusted code
executing in privileged contexts, expression injection, mutable supply-chain
references, over-broad tokens, exposed secrets — and prioritizes them by
whether attacker-controlled input can actually reach them.

## Who it's for

- **Platform / security engineers** gating merges on pipeline hygiene across
  many repositories.
- **Teams hardening CI after an incident or audit**, who need traceable
  findings with concrete remediations, not a wall of lint.

## What makes it worth building

Trigger-context reasoning. A YAML linter flags a `curl | bash` everywhere it
appears; Portcullis knows the one inside a `pull_request_target` job that
checks out PR code is a different class of problem, and escalates it. Risk is
contextual, not per-line — that judgment is encoded in the risk model, the
priority function, and the score.

## Non-goals

- **Not a general YAML linter.** Style, schema completeness, and syntax
  nits belong elsewhere.
- **Not SAST for application code.** Portcullis reads pipeline definitions,
  not the code the pipeline builds.
- **Not a whole-repo secrets scanner.** R5 covers secrets *in pipeline
  files and pipeline context* only; dedicated secret scanners cover the rest
  of the tree.
- **Not a runtime monitor.** Static, pre-merge analysis only.

## Roadmap (demand-driven)

1. Deep reusable-workflow following (the biggest fidelity gain).
2. Opt-in online mode: resolve action tags to SHAs, flag known-compromised
   versions — default stays offline.
3. More platforms behind the same normalized model: CircleCI, Azure
   Pipelines, Buildkite.
4. Auto-fix suggestions as diffs (route through `env:`, pin to SHA).
5. Richer suppression: inline `portcullis: ignore[...]` comments shipped in
   0.1.0; next is a reviewed suppression file (VEX-style, with owner and
   expiry) for org-level acceptance workflows.
