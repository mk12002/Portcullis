# PORTCULLIS — One-Shot Build Specification

*Paste this entire document into Fable 5 as a single build task. Read fully, plan once, build end-to-end in one sustained run. Do not pause for confirmation between components — build the complete system, then report honestly against the acceptance criteria.*

---

## MISSION

Build **Portcullis**, a production-quality, open-source **CI/CD pipeline security analyzer**. Portcullis statically analyzes pipeline definitions across **GitHub Actions, GitLab CI, and Jenkins**, and detects the misconfigurations behind real-world pipeline compromises: untrusted-code execution in privileged contexts, expression injection, unpinned third-party actions, over-broad token permissions, secret exposure, and dangerous trigger/permission combinations. It produces scored findings as JSON, self-contained HTML, and SARIF, with a CI merge gate.

Deliverable: a working CLI with a per-platform plugin architecture, a real detection rule set, three emitters, a fixture-based test suite, CI configuration, and complete documentation. Fully offline at scan time — no network access required or performed.

---

## NON-NEGOTIABLE CONSTRAINTS

1. **Defensive tool; inert fixtures.** Portcullis detects insecure pipelines. Test fixtures are **benign but realistic misconfigurations** — a workflow that *is* vulnerable to expression injection, but whose "payload" is an inert `echo`, never functional exploitation. Never generate a working exploit, secret-exfiltration step, or attack payload — not as an example, not commented out.
2. **No fabricated threat intel.** Do not invent CVE numbers, incident names, real-repository accusations, or statistics. Rules encode *pattern knowledge* (injection sinks, trigger risks), which is legitimate. Any real attack-class reference is named generically (e.g., "pwn-request pattern"), never with fabricated specifics.
3. **Every finding is traceable** to a concrete matched pattern at a real file:line (or workflow key path). No heuristic "this pipeline looks risky" findings.
4. **Honest confidence.** Every finding carries confidence (HIGH/MEDIUM/LOW). Data-flow reachability (does untrusted input actually reach a sink?) is often uncertain in YAML — mark it honestly. A pipeline scanner that floods PRs with false HIGHs gets disabled.
5. **Deterministic and offline.** Same input → byte-identical output (single top-level timestamp excepted). No network calls; no resolving action versions against a live registry.
6. **Never execute pipeline code.** Purely static — parse YAML/Groovy-ish structures, never run them.

---

## TARGET STACK

**Python 3.11+**, standard library first plus a YAML parser (`PyYAML` or `ruamel.yaml` — justify the choice; `ruamel` preserves line numbers, which the evidence model needs). Minimal deps, `pyproject.toml`, console entry point `portcullis`.

---

## ARCHITECTURE

```
portcullis/
  core/
    models.py          # Finding, PipelineStep, RiskAssessment, Report dataclasses; stable sort keys
    risk.py            # Scoring: rule severity + trigger-context escalation -> priority + score
    engine.py          # Orchestrates: discover pipeline files -> platform parsers -> rules -> report
    taint.py           # Lightweight untrusted-source -> sink reachability for expression injection
  platforms/
    base.py            # Platform ABC: discover(), parse(file) -> normalized Pipeline model
    github_actions.py  # .github/workflows/*.yml : jobs, steps, triggers, permissions, uses, run
    gitlab_ci.py       # .gitlab-ci.yml : jobs, rules, scripts, variables
    jenkins.py         # Jenkinsfile : declarative/scripted stage+step extraction (best-effort parse)
  rules/
    triggers.py        # R1: dangerous trigger + context (pwn-request, workflow_run)
    injection.py       # R2: expression injection via untrusted context into run/script
    pinning.py         # R3: third-party actions/images pinned to tags/branches, not SHAs
    permissions.py     # R4: over-broad token permissions / default write-all
    secrets.py         # R5: secret exposure to logs, to PR-triggered contexts, plaintext secrets
    integrity.py       # R6: curl|bash install patterns, unpinned tool downloads in steps
  emitters/
    json_emitter.py
    html_emitter.py    # self-contained, no CDN
    sarif_emitter.py   # SARIF 2.1.0
  cli.py
tests/
  fixtures/            # inert-but-vulnerable pipelines per platform + clean pipelines
  test_*.py
```

Dependency direction: `platforms` and `emitters` depend on `core`; `rules` depend on `core` (+ `taint` for R2); `core` depends on nothing internal. Each platform parser normalizes to a **common Pipeline model** (jobs → steps, with triggers, permissions, and per-step run/uses/env) so rules are written once against the normal form, not three times per platform.

---

## THE NORMALIZED PIPELINE MODEL (the key design move)

Parse each platform into one shared structure so rules are platform-agnostic:
- `Pipeline`: platform, file_path, triggers[], top-level permissions, jobs[]
- `Job`: name, permissions (override), steps[], conditions
- `Step`: name, `uses` (action/image ref + version), `run` (script text), `env`, line number
- `Trigger`: event type + qualifiers (e.g., GitHub `pull_request_target`, `workflow_run`; GitLab `rules`/MR context)

Rules operate on this model. Platform specifics (GitHub `permissions:` blocks, GitLab `variables:`, Jenkins stage syntax) are resolved during parsing, not in rules.

---

## DETECTION RULE SET (the product)

### R1 — Dangerous Triggers (`rules/triggers.py`)
- **Pwn-request pattern (GitHub):** `pull_request_target` (or `workflow_run` after a PR) **that also checks out PR head code** — grants secrets to attacker-controlled code. HIGH; CRITICAL if combined with R2 or R5 on the same job.
- **Self-hosted runner on public-repo PR triggers:** flag (persistence/lateral-movement risk).
- **Overly permissive `on:` combinations** that expose secrets to fork PRs.
- GitLab/Jenkins analogues (MR-triggered pipelines running untrusted MR scripts with protected variables).
FP note: `pull_request_target` is legitimate for labeling/triage that never touches PR code — reachability to a checkout of PR head is what escalates.

### R2 — Expression Injection (`rules/injection.py`) — the deepest rule
Detect untrusted context interpolated directly into a shell `run`/`script`:
- **Untrusted sources:** `github.event.issue.title`, `.body`, `.pull_request.title`, `.comment.body`, `.head_ref`, `.pull_request.head.ref`, and similar attacker-controllable fields; GitLab `CI_*` MR title/description variables.
- **Sink:** direct `${{ ... }}` interpolation inside a `run:` block (shell context) rather than passed via `env:` and referenced as a shell variable (the safe pattern).
- Use `core/taint.py` for lightweight source→sink reachability; mark confidence by directness. HIGH when an untrusted source lands directly in a `run` shell line.
FP note: interpolating trusted context (`github.sha`, `github.repository`) is fine; the safe remediation (route through `env:`) is the recommended fix in the report.

### R3 — Action / Image Pinning (`rules/pinning.py`)
- Third-party `uses:` pinned to a **mutable ref** (tag like `@v3` or branch like `@main`) instead of a full commit **SHA** — a supply-chain hijack vector.
- Distinguish first-party/official actions (lower urgency) from third-party (higher).
- Container images (`container:`, `services:`, Jenkins agent images) pinned to `latest` or a mutable tag rather than a digest.
MEDIUM–HIGH by third-party status. FP note: pinning to SHA has an update-burden tradeoff — the report states it rather than pretending it's free.

### R4 — Token Permissions (`rules/permissions.py`)
- Missing top-level `permissions:` (defaults to broad write on many setups) → recommend least-privilege explicit block.
- `permissions: write-all` or broad `contents: write` where the job doesn't need it.
- Jobs handling untrusted input that also hold write permissions (cross-reference R1).
MEDIUM alone; escalates with R1/R2.

### R5 — Secret Exposure (`rules/secrets.py`)
- Secrets referenced in a job reachable from an untrusted trigger (R1 cross-ref) — the exfiltration setup.
- `echo`/`print` of secret expressions, or secrets passed as command-line args (visible in process listings/logs).
- **Plaintext secrets** hardcoded in pipeline YAML (high-entropy strings in `env`/`with` — detected, redacted in output, never printed).
- Secrets in `pull_request_target` context reachable by PR code → CRITICAL with R1.
FP note: high-entropy detection has false positives (hashes, IDs); mark confidence and redact.

### R6 — Step Integrity (`rules/integrity.py`)
- `curl … | bash` / `wget … | sh` install patterns in steps (unauthenticated remote code execution into the pipeline).
- Downloading tools/binaries without checksum verification.
- Piping untrusted or unpinned URLs into interpreters.
MEDIUM–HIGH. FP note: common in legitimate setup scripts — surfaced with the checksum-verification remediation, not condemned outright.

---

## RISK MODEL (`core/risk.py`)

- Each rule fires with base severity (INFO..CRITICAL) + confidence.
- **Trigger-context escalation is first-class:** any rule firing inside a job reachable from an *untrusted trigger* (R1) escalates one severity level — the same misconfiguration is far more dangerous when attacker-controllable input can reach it. This is the core insight: pipeline risk is contextual, not per-line.
- Priority P0–P3 = deterministic function of (max severity, confidence, untrusted-reachability, corroborating-rule count on the same job).
- Project-level **pipeline security score 0–100**, transparent documented formula.
- Full (rule combination → expected priority) truth table in tests.

---

## OUTPUT EMITTERS

1. **JSON** — canonical: metadata, per-file/per-job findings (rule id, evidence file:line + YAML key path, matched snippet [inert/redacted], confidence, severity, remediation), score. Deterministic ordering (priority, file, job, rule).
2. **HTML** — single self-contained file, inline CSS, no CDN: executive summary (score + formula, priority counts, headline finding), findings table with confidence marked and untrusted-reachability flagged, per-platform/per-file breakdown, full findings with remediation ("route `github.event.issue.title` through `env:` and reference `$TITLE` in the script"), methodology + limitations footer.
3. **SARIF 2.1.0** — one rule per detection rule, results with physical locations. CI code-scanning ready.

`--format all`, `--out DIR`, `--fail-on P0..P3` exit-code gate.

---

## CLI CONTRACT

```
portcullis scan <path> [--format json|html|sarif|all] [--out DIR]
                       [--fail-on P0|P1|P2|P3]
                       [--platforms github,gitlab,jenkins]
                       [--trusted-actions PREFIX]...   # treat these uses: prefixes as first-party
                       [--quiet]
portcullis rules list        # print all rules with descriptions + FP notes
portcullis version
```
Defaults: scan cwd (auto-discover `.github/workflows/*.y*ml`, `.gitlab-ci.yml`, `Jenkinsfile`), HTML to `./portcullis-report/`, all platforms, respect `.gitignore`, warn-and-continue on unparseable files (a malformed workflow is itself a LOW finding).

---

## TESTING (mandatory; fixtures inert-but-vulnerable)

- Per platform, fixtures containing: (a) a pwn-request/untrusted-trigger job, (b) an expression-injection sink with an **inert echo payload**, (c) a third-party action pinned to a tag, (d) `write-all` permissions, (e) a secret echoed in an untrusted context, (f) a `curl|bash` step — plus one fully clean, well-secured pipeline.
- Assert exact rule firings, confidence, severity, and that **trigger-context escalation demonstrably raises severity** (same injection rule fires higher inside a `pull_request_target` job than in a push job).
- Risk-model truth-table test; emitter determinism tests; edge cases (empty workflow, matrix jobs, reusable/called workflows, non-UTF-8, deeply nested YAML anchors).
- **Inertness guard:** an automated test asserting no fixture contains a functional exploit or real secret — only inert payloads and obviously-fake secret-shaped strings.

---

## DOCUMENTATION

- `README.md`: the CI/CD threat in three sentences (pipelines hold secrets + write access + run untrusted PR code; misconfig turns that into compromise); install; quickstart; sample walkthrough; extension guide; explicit **Limitations** (static YAML analysis can't always prove reachability; reusable/called workflows are followed shallowly; high-entropy secret detection has false positives; a clean scan is evidence, not proof).
- `CONTRIBUTING.md`: adding a platform via `base.Platform`; adding a rule against the normalized model; the inert-fixture policy as a hard rule.
- `THREAT_MODEL.md` for Portcullis itself: parses untrusted pipeline files → never executes them, no network, redacts detected secrets.
- Apache-2.0 license.

---

## BUILD ORDER (single run)

1. Scaffold + pyproject + entry point.
2. `core/models.py` (incl. the normalized Pipeline model), `core/risk.py` + truth-table test, `core/taint.py` + tests.
3. `platforms/base.py`, then **GitHub Actions end-to-end**: parser → all six rules against the GitHub fixture → minimal JSON emitter. Prove the pipeline on one platform first.
4. GitLab + Jenkins parsers (normalizing to the same model), each with fixtures + tests. (Jenkins Groovy parsing is best-effort — document the limitation honestly rather than over-claiming.)
5. HTML + SARIF emitters + determinism tests.
6. Full CLI + `--fail-on` gating + robustness.
7. Edge cases + inertness guard + a dry run on a real public repo's workflows (report honestly; expect some pinning/permissions findings — that calibration note goes in the docs).
8. CI (lint, type-check, test, dogfood scan with expected exit codes).
9. Docs.
10. Self-check against acceptance criteria; report gaps truthfully.

---

## ACCEPTANCE CRITERIA

- [ ] `pip install -e .` → `portcullis scan tests/fixtures/github --format all` produces all three outputs with the known findings.
- [ ] All platform fixtures detected with correct rules, confidence, severity; trigger-context escalation demonstrably fires.
- [ ] Clean fixture yields no findings above INFO and a high score.
- [ ] Deterministic output across runs, all formats.
- [ ] `--fail-on` exit codes correct; malformed files warn, never crash.
- [ ] Inertness guard passes: no functional exploit or real secret in the repo.
- [ ] No fabricated CVEs/incidents/real-repo accusations; no network calls at scan time.
- [ ] CI green including dogfood step; docs complete with honest Limitations.

Build the complete system now. Finish with a manifest of created files, truthful acceptance-criteria results, and exact install/run commands.
