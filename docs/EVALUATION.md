# Real-world evaluation

Portcullis was run against pipeline files from **10 well-known open-source
projects** (not synthetic fixtures) to validate robustness, calibration, and
output quality, and to compare head-to-head with [zizmor](https://docs.zizmor.sh)
where the platforms overlap. This is reproducible — the method is below.

**Responsible-use note.** Nothing here claims any project is exploitable.
Findings on real repositories are *pattern observations at a stated
confidence*; several are patterns the maintainers have already reviewed and
intentionally accepted. No exploit was written, run, or attempted, and no
network access occurred during any scan.

## Dataset

| Project | Platform | Pipeline files |
|---|---|---|
| pallets/flask, pallets/click | GitHub Actions | 11 |
| tiangolo/fastapi | GitHub Actions | 22 |
| psf/requests | GitHub Actions | 8 |
| actions/runner | GitHub Actions | 13 |
| spring-projects/spring-petclinic | GitHub Actions | 3 |
| gitlab-org/gitlab-runner, gitlab-org/cli | GitLab CI | 4 |
| gitlab-com/.../common-ci-tasks | GitLab CI | 1 |
| jenkinsci/pipeline-examples | Jenkins | 4 |

**66 real pipeline files across all three platforms.**

## Robustness & performance

- **66 files scanned in ~1.4s. Zero crashes.** Real workflows include matrix
  jobs, reusable-workflow calls, anchors, multi-document YAML, and a
  deliberately-broken test fixture — all handled.
- **2 genuine parse failures** degraded to LOW `R0` findings, never crashes: a
  `.gitlab-ci.yml` test fixture with a duplicate key, and a Jenkins
  global-library Groovy file with no pipeline block. Both are correct calls.
- **Redaction held: 0 secret-value leaks** across JSON + HTML + SARIF +
  Markdown on the entire dataset.

## Calibration: the score ranking is sensible

Portcullis scored well-maintained projects high and problematic ones low,
with actionable findings driving every low score:

| Project | Score | Worst priority | Character of findings |
|---|---|---|---|
| gitlab-runner | 100 | — | clean |
| glab-cli, jenkins-examples | 99 | P3 | one low-confidence note each |
| flask, click | 95 | P2 | first-party pinning hygiene |
| requests, common-ci-tasks | 85 | P1/P2 | pinning + permissions hygiene |
| spring-petclinic | 27 | P1 | unverified downloads + broad permissions |
| actions/runner | 0 | P1 | third-party pinning + broad-write on release jobs |
| fastapi | 0 | P0 | secrets used in `workflow_run`-triggered jobs |

## Two calibration bugs this dataset caught (and we fixed)

Running on real data — not fixtures — is what surfaced these. Both fixes ship
in 0.1.0 with regression tests.

1. **Over-escalation of hygiene into P0.** Three `docker/*` actions pinned to
   version tags in `actions/runner`'s **manually-dispatched** image-publish job
   were corroborating up to **P0** (the merge-blocking bucket). P0 is meant for
   *attacker-reachable* criticals — hygiene on a trusted-trigger job shouldn't
   reach it. Fix: corroboration now floors at **P1** unless the job is
   untrusted-reachable. Result: `actions/runner` P0s went **6 → 0**, its worst
   is now a correct P1. (`test_corroboration_on_trusted_job_floors_at_p1_never_p0`)
2. **Plaintext-secret false positives.** High-entropy but structurally
   non-secret values — `platforms: linux/amd64,linux/arm64`, artifact `name:`
   fields, a `project-url:` — were flagged (correctly LOW/P3, but noisy). Fix:
   a non-secret-key denylist plus rejecting path/list/URL-shaped values.
   Result: plaintext-secret findings across the dataset went **9 → 0** with no
   loss of genuine detections. (`test_non_secret_keys_not_flagged_as_plaintext`)

Aggregate effect: dataset-wide priority mix improved from
`P0:9 P1:27 P2:72 P3:30` to **`P0:3 P1:33 P2:72 P3:21`** — the three remaining
P0s are a single genuinely-interesting true-positive class (below), not noise.

## The one P0 pattern class worth surfacing

In `fastapi`, three P0 findings flag repository secrets used inside jobs
triggered by `workflow_run` (`deploy-docs.yml`, `smokeshow.yml`), all at
**MEDIUM confidence**. `workflow_run` fires after another workflow completes —
including workflows started by fork pull requests — so a secret-using job on
that trigger is exactly the context class Portcullis is built to elevate. This
is *not* a claim of exploitability: reachability depends on details static
analysis can't fully prove (hence MEDIUM confidence), and the pattern is one
the fastapi maintainers have already reviewed and suppressed for their own
scanner. Portcullis's trigger-context lens simply re-surfaces it for a human to
confirm — which is the intended behavior.

## Head-to-head vs zizmor 1.27.0 (same inputs, offline)

zizmor is the strongest GitHub-only comparison. Run config-free on identical
inputs:

| Project | zizmor | Portcullis | Notes |
|---|---|---|---|
| flask, click, requests | clean (inline `# zizmor: ignore` in repo) | 85–95, hygiene only | strong agreement |
| spring-petclinic | 22 findings (7 high, 6 medium) | 13 findings (0 P0, 2 P1) | both flag it; both agree it needs work |
| actions/runner | **230 findings** (66 high) | **81 findings** (0 P0, 10 P1) | philosophy divergence (below) |
| GitLab / Jenkins files | **"no audit was performed"** — unsupported | scanned all 8, scores 85–100 | **Portcullis-only capability** |

Three honest takeaways:

1. **Directional agreement.** Independently, both tools rank the same projects
   healthy vs. problematic. That Portcullis flags what zizmor flags (unpinned
   actions, missing/loose permissions on `actions/runner` and
   `spring-petclinic`) is corroboration that it catches real issues, not noise.
2. **Different calibration philosophy — by design.** zizmor is lint-style: its
   blanket policy makes *every* unpinned action (first-party included) an error,
   producing 230 findings / 66 "high" on `actions/runner`. Portcullis
   distinguishes first-party (P2 hygiene) from third-party (P1), reserves P0 for
   attacker-reachable criticals, and produces 81 findings / 0 P0. The 2026
   scanner-comparison study
   ([arXiv:2601.14455](https://arxiv.org/html/2601.14455v2)) documents exactly
   this spread across tools (e.g. 125 vs 3,620 findings on one corpus) and
   recommends layering complementary scanners — Portcullis is a
   priority-first, multi-platform layer, not a zizmor replacement.
3. **Platform breadth is a real, demonstrated gap.** zizmor (and actionlint)
   are GitHub-only; on the GitLab and Jenkins files here zizmor exits with *"no
   audit was performed."* Portcullis scanned all of them through the same rule
   set. For a shop running mixed CI, that is the deciding difference.

## Reproduce it

```bash
mkdir pc-eval && cd pc-eval
for r in pallets/flask pallets/click tiangolo/fastapi psf/requests \
         actions/runner spring-projects/spring-petclinic; do
  git clone --depth 1 "https://github.com/$r" "$(basename "$r")"
done
git clone --depth 1 https://gitlab.com/gitlab-org/gitlab-runner
git clone --depth 1 https://gitlab.com/gitlab-org/cli glab-cli
git clone --depth 1 https://github.com/jenkinsci/pipeline-examples

# scan each; well-maintained repos score high, problematic ones low
for d in */; do portcullis scan "$d" --format md --out "reports/$d" --quiet; done
```

Portcullis version at evaluation: 0.1.0. zizmor version: 1.27.0.
Third-party scan outputs are intentionally **not** committed to this repo.
