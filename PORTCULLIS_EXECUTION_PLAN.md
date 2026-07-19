# PORTCULLIS — Detailed Phased Execution Plan

*A complete, phase-by-phase build plan for the Portcullis CI/CD pipeline security analyzer. Every phase has objectives, concrete tasks, deliverables, an acceptance gate, and its risks. Appendices carry the hard detail (rule catalog, scoring truth table, untrusted-source list, output schemas, test matrix, CI). Do not advance past a phase until its gate passes.*

---

## 0. How To Use This Plan

**Dual execution modes.** Hand Fable one phase at a time for control (recommended first build), or hand it `PORTCULLIS_BUILD_SPEC.md` for a single one-shot run reviewed against the gates afterward.

**You own the gates.** A gate is a hard stop; criteria must be demonstrably true before advancing. A failed gate returns you inside the current phase.

**Spine-first, one-platform-first.** Phases 1–2 build the normalized pipeline model + risk model + taint core and prove the whole pipeline on **GitHub Actions alone** before adding GitLab and Jenkins. The normalized model is the pivotal design choice — get it right once and every rule is written once, not three times.

**The shaping constraint:** fixtures are **inert-but-vulnerable** — a workflow genuinely misconfigured (real expression-injection sink, real pwn-request trigger) whose payload is a harmless `echo`. The repo demonstrates vulnerabilities without containing exploits, enforced by an automated inertness guard (Phase 6).

---

## Guiding Principles (apply in every phase)

1. **Context is the core insight.** A `curl|bash` step on a push trigger is hygiene; the same step in a job reachable from `pull_request_target` checking out PR code is a compromise. Trigger-context escalation — not per-line linting — is what makes Portcullis more than a YAML linter.
2. **Calibration over noise.** Pipeline scanners that flood PRs with false HIGHs get disabled. Confidence marking and reachability-aware escalation keep signal high.
3. **Static only, offline only, never execute.** Parse YAML/pipeline structures; never run them; never resolve action versions over the network.
4. **Every finding traceable** to a file:line + YAML key path.
5. **No fabricated intel; no real-repo accusations; redact detected secrets.**
6. **Deterministic output** for CI diffability.
7. **The inert-fixture law.** Vulnerable-looking, harmless-acting. No functional exploits, ever.

---

## Phase 0 — Foundations & Decisions

**Objective:** lock expensive decisions; stand up an empty-but-correct skeleton.

**Tasks**
- Repo + **Apache-2.0** license.
- `pyproject.toml`: Python `>=3.11`, entry point `portcullis = "portcullis.cli:main"`.
- **YAML parser decision:** choose `ruamel.yaml` (preserves line numbers — the evidence model depends on file:line accuracy) over `PyYAML`, or justify otherwise. This is the one meaningful dependency; document why.
- Dependency philosophy: stdlib-first otherwise; every dep justified in README (a security tool's own tree is attack surface).
- Full directory skeleton (empty modules + docstrings) per the build-spec architecture.
- Dev tooling: `black`, `ruff`, `mypy`, `pytest`, coverage.
- `VISION.md`: what it is, who it's for (platform/security engineers gating pipelines, teams hardening CI post-incident), **non-goals** (not a general YAML linter, not a SAST-for-app-code tool, not a secrets scanner for the whole repo — it targets *pipeline* security specifically).

**Gate 0:** `pip install -e .` works; `portcullis version` prints; `pytest` runs clean (zero tests); linter + type-checker pass; license + VISION committed.

**Risks:** wrong YAML parser choice losing line numbers (mitigate: verify line-number preservation in a spike before Phase 1); dependency bloat (mitigate: stdlib default).

---

## Phase 1 — The Spine: Normalized Model, Risk Model, Taint

**Objective:** build the dependency-free core — the normalized pipeline model, the scoring model, and the lightweight taint engine — fully tested, before any platform parser or rule exists. Highest-care phase.

**Tasks**

*1a. `core/models.py`* — the **normalized Pipeline model** (the pivotal abstraction) plus finding types:
- `Pipeline`: platform, file_path, triggers[], top-level permissions, jobs[].
- `Job`: name, permissions override, steps[], conditions, `reachable_from_untrusted` (computed flag).
- `Step`: name, uses (ref + version + first/third-party), run (script text), env, line_number, yaml_key_path.
- `Trigger`: event type + qualifiers (pull_request_target, workflow_run, MR context…).
- `Finding`, `RiskAssessment`, `Report` with stable sort keys (priority, file, job, rule).

*1b. `core/taint.py`* — lightweight untrusted-source → sink reachability:
- A curated **untrusted-source list** (Appendix C): attacker-controllable context fields per platform.
- `is_untrusted(expression)` and `reaches_sink(expression, step)` — does an untrusted source land directly in a `run` shell context vs. safely via `env`?
- Deliberately simple (string/context analysis, not full dataflow); confidence reflects the simplicity honestly.

*1c. `core/risk.py`* — scoring (Appendix B truth table):
- Base severity + confidence per rule.
- **Trigger-context escalation:** a rule firing in a job where `reachable_from_untrusted` is true escalates one severity level — first-class, the core insight.
- Priority P0–P3 = deterministic function of (max severity, confidence, untrusted-reachability, corroborating count).
- `pipeline_score(report) -> 0..100`, transparent documented formula.

**Tests (required for the gate):**
- Taint: crafted expressions classify correctly (untrusted-in-run → reachable; same source via env → safe); truth cases for each untrusted source.
- Risk: full Appendix B truth table, including trigger-context escalation and corroboration.
- Models: determinism under shuffle-then-sort.

**Gate 1:** truth-table + taint tests 100% green; escalation demonstrably changes priority; determinism holds. **No platform parser or rule exists yet.**

**Risks:** taint engine too naive → misses/false-alarms (mitigate: confidence honesty + documented limitation, not silent overclaim); escalation logic errors mis-prioritizing everything (mitigate: truth table reviewed before lock).

---

## Phase 2 — Walking Skeleton: GitHub Actions, End-to-End

**Objective:** prove discover → parse-to-normalized-model → all-six-rules → assess → emit on **GitHub Actions only**, minimal JSON emitter. Riskiest integration; do it on one platform before the others.

**Tasks**
- `platforms/base.py`: the `Platform` ABC — `discover(root)`, `parse(file) -> Pipeline`.
- `platforms/github_actions.py`: parse `.github/workflows/*.y*ml` into the normalized model — jobs, steps, triggers, top-level + job `permissions`, `uses` refs (classify first vs third-party), `run` blocks, `env`, with accurate line numbers. Compute `reachable_from_untrusted` per job from triggers.
- All six rule modules against GitHub:
  - `triggers.py` (pwn-request, workflow_run, self-hosted-on-PR)
  - `injection.py` (untrusted context → run sink, via `core/taint`)
  - `pinning.py` (tag/branch vs SHA; image tags vs digests)
  - `permissions.py` (missing block, write-all, over-broad)
  - `secrets.py` (secret in untrusted context, echoed secrets, plaintext high-entropy — redacted)
  - `integrity.py` (curl|bash, unverified downloads)
- `core/engine.py` (minimal): discover → GitHub parser → rules → risk → Report.
- `emitters/json_emitter.py` (minimal, deterministic).
- `cli.py` (minimal): `portcullis scan <path> --format json`.
- **GitHub fixture** (`tests/fixtures/github/`), inert-but-vulnerable: a `pull_request_target` job that checks out PR head and echoes an injected title (inert), a third-party action pinned `@v3`, `permissions: write-all`, a `curl|bash` step, and known-answer comments.

**Gate 2 (critical):** `portcullis scan tests/fixtures/github --format json` finds exactly the known issues at correct confidence/severity, **the injection inside `pull_request_target` escalates to CRITICAL** while an identical pattern on `push` does not, and JSON is valid + deterministic across two runs. Pipeline proven → fan-out safe.

**Risks:** matrix jobs / reusable workflows complicating parsing (fixture must include a matrix job); escalation not wired through to rules (that's exactly what Gate 2 checks).

---

## Phase 3 — Platform Fan-Out

**Objective:** add GitLab and Jenkins, normalizing both into the same model so rules run unchanged.

**Tasks (one sub-cycle each):**
- `gitlab_ci.py`: parse `.gitlab-ci.yml` — jobs, `script`/`before_script`, `rules`/`only`/`except` (→ triggers), `variables`, MR context. Map protected-variable + MR-trigger risks to the normalized untrusted-reachability flag.
- `jenkins.py`: **best-effort** parse of declarative and scripted `Jenkinsfile` (Groovy) — extract stages, steps, `sh` blocks, credentials usage. Groovy is not cleanly YAML-parseable; use a pragmatic structural parse and **document the reduced fidelity honestly** rather than pretending full coverage. Rules apply where the parse is confident; low-confidence where structural.
Each ships an inert-but-vulnerable fixture + a test asserting exact firings, reusing the same rule modules (proof the normalized model works).

**Gate 3:** GitLab and Jenkins fixtures pass; a whole-tree scan yields the complete known-answer set across all three platforms with the same rule code; Jenkins limitations documented, not masked. False positives acceptable only if correctly low-confidence; fixture false negatives are not.

**Risks:** Jenkins/Groovy parse brittleness (mitigate: best-effort + honest low-confidence + documented limitation — do not overclaim); GitLab `rules:` semantics complexity (mitigate: conservative mapping, surfaced confidence).

---

## Phase 4 — Emitters: HTML + SARIF, JSON Hardening

**Objective:** complete all three outputs to production quality.

**Tasks**
- `html_emitter.py` (Appendix E): single self-contained file, inline CSS, no CDN. Executive summary (score + formula, priority counts, headline), findings table with confidence + untrusted-reachability visibly flagged, per-platform/per-file breakdown, full findings with concrete remediation, methodology + limitations footer. Zero fabricated numbers; secrets redacted.
- `sarif_emitter.py`: SARIF 2.1.0 — rule per detection rule, results with physical locations (file + region), messages. Validates against schema shape.
- Harden `json_emitter.py`: full fields, deterministic ordering.
- `--format all`, `--out DIR`.

**Gate 4:** HTML renders standalone offline and reads well to a non-author; SARIF validates and locates findings; JSON deterministic; `--format all` consistent across formats.

**Risks:** secrets leaking into HTML/JSON evidence (mitigate: redaction tested explicitly); HTML overstating uncertain reachability findings (mitigate: confidence + reachability surfaced per row).

---

## Phase 5 — Orchestration, CLI, CI Gating

**Objective:** finish the CLI contract; make Portcullis CI-ready.

**Tasks (full CLI in Appendix F):**
- Flags: `--format`, `--out`, `--fail-on`, `--platforms`, `--trusted-actions` (repeatable, mark prefixes first-party), `--quiet`.
- `--fail-on P0..P3`: exit non-zero at/above threshold — the merge gate.
- `portcullis rules list`: print every rule + FP note.
- Robustness: unparseable workflow → warn + LOW finding, continue; never crash a scan on one bad file.
- Auto-discovery of all three platforms' files; respect `.gitignore`.

**Gate 5:** `--fail-on P0` returns non-zero with a P0 present, zero otherwise; `--platforms`/`--trusted-actions` filter correctly; malformed workflow → warning + LOW finding, not a crash; `rules list` prints the catalog.

**Risks:** silent parse failures (mitigate: warn-and-continue + skipped-files summary); scope creep into general secret scanning (mitigate: VISION non-goals — pipeline-scoped).

---

## Phase 6 — Testing, Hardening, Inertness Guard

**Objective:** raise confidence from "passes fixtures" to "trustworthy and safe."

**Tasks**
- Coverage: meaningful on `core/`, `rules/`, `taint`.
- Determinism across all three formats.
- Edge cases: empty workflow, matrix jobs, reusable/called workflows (`uses: ./.github/...` and remote), YAML anchors/aliases, non-UTF-8, multi-document YAML, a job with no steps.
- **Inertness guard (mandatory):** automated test scanning the repo's own fixtures asserting no functional exploit, no real secret (only obviously-fake secret-shaped strings), no live payload URLs.
- False-positive tuning: run on 3–5 **real** public repos' workflows; audit a sample; tune confidence bands; record FP characteristics honestly in docs.
- Parser fuzzing: malformed pipeline files degrade gracefully, never execute anything.

**Gate 6:** full suite green; determinism holds; inertness guard passes; real-repo runs complete cleanly with calibrated results; clean fixture scores high, vulnerable fixtures low.

**Risks:** over-tuning to test repos (mitigate: variety in the audit set; rules are the source of truth).

---

## Phase 7 — Packaging & CI/CD

**Objective:** trivially installable, self-verifying (Appendix H).

**Tasks**
- Finalize `pyproject.toml`; verify clean fresh-venv install.
- GitHub Actions: matrix over Python versions → install → `ruff` → `mypy` → `pytest` + coverage → **dogfood**: Portcullis scans its own fixtures asserting expected exit codes (the CRITICAL fixture trips `--fail-on P0`). Bonus irony/credibility: Portcullis's own CI is a clean, SHA-pinned, least-privilege workflow — it passes its own scan.
- Release workflow (tag → build → optional PyPI). Tagged GitHub release suffices for v1.
- A copy-paste "Portcullis as a CI gate" snippet.

**Gate 7:** CI green on clean checkout; fresh-venv install works; tagged release; the gate snippet works pasted; **Portcullis's own workflows pass Portcullis** (dogfooding credibility).

**Risks:** environment-specific install bugs (mitigate: fresh-venv test); CI not actually running the tool (mitigate: dogfood mandatory).

---

## Phase 8 — Documentation

**Objective:** documentation good enough for unaided adoption and contribution.

**Tasks**
- `README.md`: the CI/CD threat in three sentences; install; quickstart; sample-report walkthrough; extension pointer; explicit **Limitations** (static reachability is approximate; Jenkins/Groovy parse is best-effort; reusable workflows followed shallowly; high-entropy secret detection has FPs; clean scan = evidence, not proof).
- `CONTRIBUTING.md`: add a platform via `base.Platform`; add a rule against the normalized model; the inert-fixture policy as a hard rule.
- `THREAT_MODEL.md` for Portcullis itself: parses untrusted pipeline files → never executes, no network, redacts secrets.
- Docstrings on every public function; rule catalog commented with FP rationale; Apache-2.0.

**Gate 8:** a newcomer installs, runs, interprets a report from the README alone; a contributor adds a trivial rule from CONTRIBUTING alone; Limitations honest and present.

**Risks:** overselling (mitigate: write Limitations first).

---

## Phase 9 — Launch & Proof-of-Work

**Objective:** convert the tool into public credibility.

**Tasks**
- Run on several well-known public repos; capture honest results (pinning/permissions findings are common and legitimate to show — they're hygiene, not zero-days). **If you find a genuinely exploitable pwn-request in a real project: coordinate disclosure privately; never publish a working exploit or name-and-shame unverified.** Hard rule.
- Launch post (LinkedIn + longer README/blog): the pipeline-security problem, what Portcullis catches that YAML linters don't (the trigger-context reasoning), a real sample report, honest limitations. Proof-of-work over proclamation; acknowledge prior art (existing pipeline-security tools) and position on the normalized-model + injection-reachability angle.
- Tagged v0.1.0 + changelog; optional 90-second demo GIF.
- File good-first-issues (add platform X, add rule Y).

**Gate 9:** public, installable, documented; launch post links a reproducible run; ≥1 good-first-issue filed; Portcullis's own repo passes Portcullis.

**Risks:** irresponsible disclosure (mitigate: coordinated disclosure, no exploit/naming); overclaiming novelty (mitigate: acknowledge prior art honestly).

---

## Phase 10 — Post-Launch Roadmap (demand-driven)

- **Reusable-workflow following:** resolve and analyze `uses:`-called local/remote workflows deeply — the biggest fidelity gain.
- **Optional online mode (opt-in):** resolve action tags to current SHAs and flag actions with known-compromised versions — keep default offline.
- **More platforms:** CircleCI, Azure Pipelines, Buildkite — each a clean `Platform` addition to the normalized model.
- **Auto-fix suggestions:** emit the corrected YAML (route injection through `env:`, pin to SHA) as a diff.
- **VEX-style suppression:** accept-and-annotate specific findings so CI stays intentionally green.
- **Pairing:** a combined report across Portcullis + Stowaway + Lattice — the supply-chain-to-crypto portfolio thesis made literal.

Each item = its own mini-cycle against the existing spine.

---

## Master Risk Register

| Risk | Phase | Severity | Mitigation |
|---|---|---|---|
| Functional exploit or real secret in fixtures | all | Critical | Inert-fixture law + automated inertness guard (Phase 6) |
| False HIGH flood erodes trust | 1,3,6 | High | Trigger-context escalation + confidence bands + real-repo tuning |
| Executing pipeline code during analysis | 2,3 | Critical | Static-only parse; fuzzed malformed inputs never run |
| Wrong escalation logic mis-prioritizes everything | 1 | High | Truth table reviewed before Gate 1 |
| Jenkins/Groovy parse overclaimed | 3,8 | Medium | Best-effort + honest low-confidence + documented limitation |
| Detected secret leaked into report output | 4 | High | Redaction tested explicitly |
| Naming a real repo as exploitable at launch | 9 | High | Coordinated disclosure; never publish unverified |
| Line numbers lost → untraceable findings | 0 | Medium | ruamel.yaml choice verified in a Phase-0 spike |

---

## Master Definition of Done (v1)

- [ ] Clean-venv `pip install` → `portcullis scan <repo>` produces JSON + HTML + SARIF.
- [ ] All three platforms + all six rules pass fixture tests; trigger-context escalation fires.
- [ ] Risk truth table + taint tests 100% green.
- [ ] Deterministic output across runs in all formats.
- [ ] `--fail-on` gates correctly; malformed input never crashes.
- [ ] Inertness guard passes; no functional exploit or real secret in the repo; secrets redacted in output.
- [ ] No network calls at scan time; no fabricated intel; no unverified real-repo accusations.
- [ ] CI green, dogfoods Portcullis on its own fixtures, and Portcullis's own workflows pass Portcullis.
- [ ] README (honest Limitations), CONTRIBUTING (inert-fixture rule), THREAT_MODEL complete.
- [ ] Public tagged release + launch post linking a reproducible run.

---

# Appendix A — Rule Catalog (id · signal · base severity · confidence · FP note)

**R1 Dangerous triggers** · `pull_request_target`/`workflow_run` reachable to PR-head checkout; self-hosted runner on public PR · HIGH (CRITICAL with R2/R5) · confidence HIGH when checkout of PR head is present · *FP: pull_request_target for labeling that never touches PR code.*

**R2 Expression injection** · untrusted context (Appendix C) interpolated directly into a `run`/`script` shell line · HIGH · confidence by directness of source→sink · *FP: trusted context (github.sha) is safe; fix = route via env.*

**R3 Pinning** · third-party `uses:`/image on mutable tag/branch, not SHA/digest · MEDIUM (HIGH third-party) · *FP: SHA pinning has update-burden tradeoff, stated not hidden.*

**R4 Permissions** · missing `permissions:` block / write-all / over-broad for the job · MEDIUM (escalates with R1) · *FP: some jobs legitimately need contents:write.*

**R5 Secret exposure** · secret reachable from untrusted trigger / echoed / plaintext high-entropy in YAML · HIGH (CRITICAL with R1) · secret values redacted · *FP: high-entropy detection hits hashes/IDs — confidence-marked.*

**R6 Step integrity** · `curl|bash`, unverified tool download, untrusted URL piped to interpreter · MEDIUM–HIGH · *FP: common legitimate setup — remediation is checksum verification.*

---

# Appendix B — Risk Scoring Truth Table (risk.py must satisfy)

| Findings on a job | Priority | Rationale |
|---|---|---|
| R2 injection inside untrusted-trigger job | **P0** | Attacker input reaches shell with secrets present |
| R1 pwn-request + secret reachable (R5) | **P0** | Classic secret-exfil setup |
| R5 secret echoed in untrusted context | **P0** | Direct exposure path |
| R2 injection on a trusted (push) trigger | **P1** | Real but not attacker-reachable externally |
| R1 dangerous trigger alone (no sink yet) | **P1** | Risky surface; verify reachability |
| R3 third-party action on mutable tag | **P1** | Supply-chain hijack vector |
| R4 write-all in an untrusted-reachable job | **P1** | Over-privilege where it's dangerous |
| R6 curl\|bash on trusted trigger | **P2** | Integrity risk, limited external reach |
| R3 first-party action on tag | **P2** | Lower urgency (trusted publisher) |
| R4 missing permissions block, low-risk job | **P2** | Hygiene; least-privilege recommended |
| Two independent MEDIUMs on one job | **P1** | Corroboration outranks isolated MEDIUM |
| One low-confidence finding | **P3** | Surface, don't block; verify |
| Clean / trusted context / SHA-pinned | **None** | No action |

*Precedence: trigger-context escalation applies first (untrusted-reachable → +1 severity); then max severity; confidence + corroboration break ties.*

---

# Appendix C — Untrusted Source List (taint.py)

**GitHub (attacker-controllable):** `github.event.issue.title`, `.issue.body`, `.pull_request.title`, `.pull_request.body`, `.pull_request.head.ref`, `.pull_request.head.repo.*`, `.comment.body`, `.review.body`, `.head_commit.message`, `.head_ref`, `github.head_ref`. **Trusted (safe):** `github.sha`, `github.repository`, `github.actor` (with care), `github.run_id`.

**Safe pattern (recommended remediation):** pass untrusted context through `env:` and reference it as a shell variable (`env: TITLE: ${{ github.event.issue.title }}` then `run: echo "$TITLE"`), never interpolate `${{ ... }}` directly into a `run` shell line.

**GitLab:** MR-title/description variables and other MR-context `CI_*` values controllable by the MR author; protected variables exposed to MR-triggered pipelines.

---

# Appendix D — Normalized Pipeline Model (the pivotal abstraction)

All three parsers emit this so rules are written once:
```
Pipeline(platform, file_path, triggers[Trigger], permissions, jobs[Job])
Job(name, permissions, steps[Step], conditions, reachable_from_untrusted: bool)
Step(name, uses: {ref, version, party}, run: str, env: dict, line, yaml_key_path)
Trigger(event, qualifiers)   # e.g. event="pull_request_target"
```
`reachable_from_untrusted` is computed at parse time from triggers and is the input to risk escalation. Adding a platform = writing a parser to this model; adding a rule = a function over this model.

---

# Appendix E — HTML Report Structure

1. **Header:** target, scan time, version, platforms scanned.
2. **Executive band:** pipeline security score (0–100, prominent) + formula line; priority counts; headline (e.g., "1 workflow allows attacker-controlled input to reach a shell with repository secrets").
3. **Priority table:** file · job · rules · confidence (marked) · untrusted-reachable (flagged) · severity · priority · remediation.
4. **Per-platform/per-file breakdown.**
5. **Full findings:** grouped by priority; inert/redacted evidence + concrete fix ("route through env:", "pin to SHA", "scope permissions to contents:read").
6. **Methodology & limitations footer.** Every number from real findings; secrets redacted.

Single file, inline CSS, no external requests.

---

# Appendix F — CLI Reference

```
portcullis scan <path>
    --format {json,html,sarif,all}   default: html
    --out DIR                        default: ./portcullis-report
    --fail-on {P0,P1,P2,P3}          exit nonzero if findings >= threshold
    --platforms LIST                 e.g. github,gitlab,jenkins
    --trusted-actions PREFIX         repeatable; treat as first-party (lower pinning urgency)
    --quiet
portcullis rules list                print rule catalog + FP notes
portcullis version
```
Auto-discovers `.github/workflows/*.y*ml`, `.gitlab-ci.yml`, `Jenkinsfile`. Respects `.gitignore`. Unparseable file → warn + LOW finding, continue.

---

# Appendix G — Test Matrix

| Suite | Asserts |
|---|---|
| Taint | untrusted sources classified; run-sink vs env-safe distinction |
| Risk model | full Appendix B truth table incl. trigger-context escalation |
| Models | deterministic sort under shuffle |
| Per-platform (×3) | exact rule firings, confidence, severity on inert fixtures |
| Escalation | injection in pull_request_target → CRITICAL; same on push → lower |
| Emitters (×3) | schema validity + byte-determinism across two runs; secret redaction |
| Engine | discovery + .gitignore + matrix/reusable-workflow handling |
| Edge cases | empty/matrix/reusable/anchors/non-UTF-8/multi-doc/no-steps |
| **Inertness guard** | no functional exploit or real secret in any fixture |
| CLI | `--fail-on` exit codes; `--platforms`/`--trusted-actions` filtering; malformed resilience |
| Dogfood (CI) | Portcullis scans own fixtures; own workflows pass Portcullis |

---

# Appendix H — GitHub Actions (shape; itself a clean, SHA-pinned, least-privilege example)

```yaml
name: ci
on: [push, pull_request]
permissions:
  contents: read            # least privilege — Portcullis passes its own R4
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix: { python: ["3.11", "3.12"] }
    steps:
      - uses: actions/checkout@<full-sha>       # SHA-pinned — passes its own R3
      - uses: actions/setup-python@<full-sha>
        with: { python-version: "${{ matrix.python }}" }
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: mypy portcullis
      - run: pytest --cov=portcullis --cov-report=term-missing
      # dogfood: the CRITICAL github fixture must trip the gate
      - run: portcullis scan tests/fixtures/github --fail-on P0 || test $? -eq 1
```

The workflow is written to **pass Portcullis's own rules** (SHA-pinned actions, least-privilege permissions) — the dogfooding is both a functional test and a credibility signal.

---

*Build the normalized model and the risk truth table with disproportionate care, prove the pipeline on GitHub Actions, then fan out to GitLab and Jenkins against the same model. Every gate is a real stop. The inert-fixture law is absolute. Trigger-context reasoning — not per-line linting — is what makes Portcullis worth building.*
