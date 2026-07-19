# Portcullis

**Static security analyzer for CI/CD pipeline definitions — GitHub Actions, GitLab CI, and Jenkins.**

CI/CD pipelines hold repository secrets, carry write-capable tokens, and routinely execute code from untrusted pull requests. A single misconfiguration — a `pull_request_target` job that checks out PR code, a PR title interpolated into a shell line, a third-party action on a mutable tag — turns that combination into full repository compromise. Portcullis statically detects those misconfigurations before they ship, and scores them by *context*: the same flaw is far more dangerous where attacker-controlled input can reach it.

- **Purely static and fully offline.** Pipeline files are parsed, never executed. No network access at scan time.
- **Three platforms, one rule set.** Every parser normalizes to a shared pipeline model, so rules are written once.
- **Three outputs.** Canonical JSON, a self-contained HTML report (no CDN), and SARIF 2.1.0 for code scanning.
- **A real merge gate.** `--fail-on P0..P3` exit codes for CI.

## Install

```bash
pip install -e .            # from a checkout
pip install -e ".[dev]"     # with dev tooling (pytest, ruff, mypy)
```

Requires Python 3.11+. The single runtime dependency is `ruamel.yaml`, chosen because its round-trip loader preserves line numbers — every Portcullis finding must be traceable to a real `file:line`, which PyYAML cannot provide.

## Quickstart

```bash
# scan the current repository, write an HTML report to ./portcullis-report/
portcullis scan .

# all three formats, gate the merge on P0 findings
portcullis scan . --format all --out ./portcullis-report --fail-on P0

# see every rule with its false-positive notes
portcullis rules list
```

Try it on the bundled inert fixtures:

```bash
portcullis scan tests/fixtures/github --format all --out ./demo-report
```

Expected console output:

```
portcullis v0.1.0 — scanned 2 pipeline file(s)
score: 0/100 · P0:6 P1:4 P2:0 P3:0
top finding: [P0/CRITICAL] R1 pwn-request at .github/workflows/vulnerable.yml:21
```

## Reading a report

The HTML report opens with the **pipeline security score** (0–100, formula printed beside it: `max(0, 100 - 30·|P0| - 15·|P1| - 5·|P2| - 1·|P3|)`), priority counts, and the headline finding. Each finding row shows:

- **Priority P0–P3** — deterministic function of severity, confidence, untrusted-reachability, and corroborating rules on the same job.
- **Severity with ↑ marker** — findings inside a job reachable from an untrusted trigger (e.g. `pull_request_target`) are escalated one level. This is the core idea: a `curl | bash` on a push trigger is hygiene; the same step where attacker-controlled input reaches it is an incident waiting to happen.
- **Confidence HIGH/MEDIUM/LOW** — honest uncertainty. Static YAML analysis cannot always prove reachability; LOW-confidence findings are surfaced at P3 and never block a merge.
- **Evidence at `file:line`** plus a YAML key path, and a concrete remediation (e.g. *route `github.event.issue.title` through `env:` and reference `"$TITLE"` in the script*).

## The rules

| Rule | Detects |
|---|---|
| R1 | Dangerous triggers: pwn-request pattern (`pull_request_target`/`workflow_run` + PR-head checkout), self-hosted runners on PR events, MR pipelines touching credentials |
| R2 | Expression injection: untrusted context (PR/issue titles & bodies, comments, refs, `CHANGE_*`, MR variables) interpolated directly into shell/script lines |
| R3 | Pinning: third-party actions on mutable tags/branches instead of commit SHAs; container images on `latest`/tags instead of digests |
| R4 | Token permissions: missing `permissions:` block, `write-all`, over-broad write scopes |
| R5 | Secret exposure: secrets reachable from untrusted triggers, echoed to logs, passed as argv, or hardcoded in plaintext (always redacted in output) |
| R6 | Step integrity: `curl \| bash` installs, downloads without checksum verification |

`portcullis rules list` prints the full catalog including per-rule false-positive notes.

## Using Portcullis as a CI gate

```yaml
- name: pipeline security gate
  run: |
    pip install portcullis-scanner
    portcullis scan . --format sarif --out ./portcullis-report --fail-on P0
```

Portcullis's own CI does exactly this — and its own workflow is SHA-pinned and least-privilege, so it passes its own scan (see `.github/workflows/ci.yml` and `tests/test_dogfood.py`).

## Extending

Adding a platform means implementing `platforms.base.Platform` (two methods: `matches`, `parse`) and emitting the normalized `Pipeline` model; every existing rule then applies automatically. Adding a rule means one function over that model. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Limitations (read this)

- **Reachability is approximate.** Static analysis of YAML cannot always prove that untrusted input reaches a sink at runtime. Confidence levels mark that honestly; treat MEDIUM/LOW-confidence findings as leads, not verdicts.
- **Reusable/called workflows are followed shallowly.** The `uses:` reference is analyzed (pinning, party); the called workflow's own content is not fetched or parsed.
- **Jenkinsfile parsing is best-effort.** Groovy cannot be parsed faithfully without evaluating it, which Portcullis will never do. Jenkins findings are structural and capped at MEDIUM confidence.
- **High-entropy secret detection has false positives** (hashes, opaque IDs). Such findings carry LOW confidence, and detected values are redacted in every output format.
- **A clean scan is evidence, not proof.** Portcullis checks known misconfiguration patterns; it does not certify a pipeline as secure.
- `.gitignore` handling is a pragmatic subset (no negation patterns).

## Test fixtures are inert by law

The repository ships deliberately vulnerable pipeline fixtures for testing. They are **inert-but-vulnerable**: genuinely misconfigured (real injection sinks, real pwn-request triggers) but with harmless `echo` payloads, `example.com` URLs, and obviously fake secret-shaped strings. An automated inertness guard (`tests/test_inertness.py`) enforces this on every run. See [THREAT_MODEL.md](THREAT_MODEL.md).

## License

Apache-2.0.
