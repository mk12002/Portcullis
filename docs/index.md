# Portcullis

**Static security analyzer for CI/CD pipeline definitions — GitHub Actions, GitLab CI, and Jenkins.**

CI/CD pipelines hold repository secrets, carry write-capable tokens, and routinely execute code from untrusted pull requests. One misconfiguration turns that combination into full repository compromise. Portcullis detects those misconfigurations statically and — unlike a linter — ranks each finding by whether an attacker can actually reach the job it's in.

![Architecture](images/architecture.svg)

## Why Portcullis

- **Three platforms, one model.** GitHub Actions, GitLab CI, and Jenkins are normalized into one shared model, so every rule runs on every platform.
- **Context is the ranking backbone.** A finding inside a job reachable from an untrusted trigger is escalated one severity level — the merge-blocking `P0` bucket is reserved for attacker-reachable criticals.
- **Static, offline, deterministic.** Never executes your pipeline, never touches the network at scan time, and produces byte-identical output for the same input.
- **Four outputs.** Canonical JSON, self-contained HTML (CSP-hardened), **SARIF 2.1.0** (schema-validated), and PR-comment Markdown.
- **Honest.** Every finding carries a confidence level; low-confidence findings never block a merge.

## 30-second start

```bash
pip install -e .          # from a checkout
portcullis scan . --fail-on P0
```

See [Installation](installation.md), the [CLI Reference](cli.md), and runnable [Examples](examples.md).

## The detection rules

| Rule | Catches |
|---|---|
| R1 | Dangerous triggers — pwn-requests, artifact poisoning, self-hosted runners on PRs |
| R2 | Expression injection — untrusted text into shell/script lines |
| R3 | Pinning — actions/images on mutable tags instead of SHAs/digests |
| R4 | Token permissions — over-broad / write-all / `secrets: inherit` |
| R5 | Secret exposure — echoed, argv-passed, untrusted-reachable, or hardcoded |
| R6 | Step integrity — `curl \| bash`, unverified downloads, insecure commands |

Full catalog with false-positive notes: [Detection Rules](rules.md).

## Proven on real pipelines

Run against **66 real pipeline files from 10 well-known OSS projects** — zero crashes, sensible ranking, validated head-to-head against zizmor. See [Real-world Evaluation](EVALUATION.md) and [Benchmarks](benchmarks.md).
