# Architecture

Portcullis is a pipeline of five stages: **discover → parse → normalize → assess
→ emit**. The keystone is the *normalized model* — every platform parser converts
its format into one shared structure, so detection rules are written once and
apply to all platforms.

![Architecture](images/architecture.svg)

## The normalized model (parse once, rule once)

Without it, each rule would be reimplemented per platform — O(rules × platforms).
Every parser instead emits:

```
Pipeline(platform, triggers[], permissions, jobs[], capabilities, fidelity)
  Job(name, permissions, steps[], images[], reachable_from_untrusted)
    Step(name, uses, run, env, with_, shell, line, ...)
  Trigger(event, untrusted_privileged, untrusted_input)
```

Rules operate on that. Adding a platform is one parser (all rules apply free);
adding a rule is one function (works on all platforms free) — O(rules + platforms).

## Module layout (src layout)

```
src/portcullis/
  core/       models.py (normalized model) · taint.py · risk.py · engine.py
  platforms/  base.py · github_actions.py · gitlab_ci.py · jenkins.py
  rules/      triggers R1 · injection R2 · pinning R3 · permissions R4
              secrets R5 · integrity R6 · common.py
  emitters/   json · html · sarif · md
  cli.py · logging_config.py · py.typed
```

Dependencies point **inward**: `core/` depends on nothing internal; parsers,
rules, and emitters depend on `core`; the engine and CLI wire them together.

## The core insight: trigger-context escalation

A finding inside a job an attacker can reach (`reachable_from_untrusted`) is
escalated one severity level. The same expression-injection is `HIGH`/`P1` on a
`push` trigger and `CRITICAL`/`P0` under `pull_request_target`. This — not
per-line linting — is what makes Portcullis a risk-ranker, and it reserves the
merge-blocking `P0` bucket for genuinely reachable criticals.

Priority `P0–P3` is a deterministic function of severity, confidence,
reachability, and corroboration; the pipeline security score is a transparent
formula printed on every report:

```
score = max(0, 100 − 30·|P0| − 15·|P1| − 5·|P2| − 1·|P3|)
```

## Guarantees

Static-only (never executes pipeline content) · offline (no network at scan
time) · deterministic output · warn-and-continue (one bad file never aborts a
scan) · hardened against alias bombs, oversized files, symlink traversal, and
report XSS. See the [Threat Model](THREAT_MODEL.md).
