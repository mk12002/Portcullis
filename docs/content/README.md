# Portcullis — content & launch kit

Everything you need to showcase Portcullis publicly: three ready-to-publish
blog posts, a 12-day Twitter/X thread series, LinkedIn posts, and exact
instructions for **how, when, and where** to post each one.

Built to the [BLOG_CREATION_PLAYBOOK](../../..) 6-phase method. Every blog is
written to be understood by **both technical and non-technical readers**:
each opens with a plain-language "For everyone" framing, then goes deep for
engineers. Diagrams are inline Mermaid (render natively on GitHub, Hashnode,
and Dev.to) plus the polished SVGs in [`images/`](images/) and
[`../images/`](../images/). `[SCREENSHOT: …]` markers show where to drop your
own captures.

## What's in here

| File | What it is | Best platform |
|---|---|---|
| [`blog-1-anatomy-of-a-pipeline-hack.md`](blog-1-anatomy-of-a-pipeline-hack.md) | Threat-education: how a pipeline gets compromised, in plain terms then deep | Hashnode / Dev.to / Medium |
| [`blog-2-i-scanned-10-famous-repos.md`](blog-2-i-scanned-10-famous-repos.md) | Build story + real data: what scanning 10 well-known repos showed | Hashnode / Dev.to / r/netsec |
| [`blog-3-context-is-everything.md`](blog-3-context-is-everything.md) | Technical deep-dive: the trigger-context insight that beats linting | Hashnode / Dev.to / Lobsters |
| [`twitter-12-day-series.md`](twitter-12-day-series.md) | 12 daily threads, each self-contained, with post times | Twitter/X |
| [`linkedin-posts.md`](linkedin-posts.md) | 3 LinkedIn posts (one per blog) | LinkedIn |

## Before you post anything (one-time setup, ~30 min)

1. **Publish the repo** to GitHub (public). Replace every `<you>` /
   `github.com/<you>/portcullis` placeholder in the blogs and threads with your
   real URL. Tag a `v0.1.0` release so links are stable.
2. **Capture 4 screenshots** (the blogs reference these — 10 minutes):
   - `SCREENSHOT: terminal-scan` — run `portcullis scan tests/fixtures/github --format all` in a clean terminal.
   - `SCREENSHOT: html-report` — open `docs/sample-report/report.html`, screenshot the score band + findings table.
   - `SCREENSHOT: ci-gate` — the `--fail-on P0` run showing exit code 1.
   - `SCREENSHOT: real-repo-scan` — a scan of any public repo you like (the Markdown output reads well).
   Drop them in `images/` and update the `[SCREENSHOT: …]` markers, or paste directly into the blog editor.
3. **Accounts**: [Hashnode](https://hashnode.com) (primary blog, free), [Dev.to](https://dev.to) (cross-post), Twitter/X, LinkedIn. Optional: Medium (InfoSec Write-ups publication).

## The 12-day launch calendar

Post **one thing per day** for 12 days. Consistency beats a single big splash.
All times are **your local time**; the windows below are tuned for a
US/EU-tech-Twitter audience — shift by your timezone.

| Day | Post | Where | Best time |
|---|---|---|---|
| **1 (Tue)** | 🚀 Launch: Blog 2 (build story) | Hashnode → Dev.to cross-post | Publish 14:00 UTC |
| 1 | Twitter Thread #1 (the hook + launch) | Twitter/X | 15:00–17:00 UTC (Tue–Thu peak) |
| 1 | LinkedIn post #2 (build story) | LinkedIn | 13:00–15:00 UTC (Tue–Thu) |
| **2 (Wed)** | Twitter Thread #2 (the one-line problem) | Twitter/X | 15:00 UTC |
| **3 (Thu)** | Blog 1 (threat education) | Hashnode → Dev.to | 14:00 UTC |
| 3 | Twitter Thread #3 (pwn-request explained) | Twitter/X | 16:00 UTC |
| **4 (Fri)** | Twitter Thread #4 (expression injection) | Twitter/X | 15:00 UTC |
| **5 (Sat)** | Submit Blog 2 to **r/netsec** + **r/devops** | Reddit | 14:00–16:00 UTC Sat |
| **6 (Sun)** | Twitter Thread #5 (real-repo results) | Twitter/X | 17:00 UTC Sun |
| **7 (Mon)** | Twitter Thread #6 (zizmor comparison, respectful) | Twitter/X | 15:00 UTC |
| **8 (Tue)** | Blog 3 (deep dive) | Hashnode → Dev.to | 14:00 UTC |
| 8 | Twitter Thread #7 (trigger-context insight) | Twitter/X | 16:00 UTC |
| 8 | LinkedIn post #3 (deep dive) | LinkedIn | 13:00 UTC |
| **9 (Wed)** | Twitter Thread #8 (the risk score) | Twitter/X | 15:00 UTC |
| **10 (Thu)** | Twitter Thread #9 (multi-platform: GitLab + Jenkins) | Twitter/X | 16:00 UTC |
| **11 (Fri)** | Twitter Thread #10 (inert-fixture / responsible design) | Twitter/X | 15:00 UTC |
| **12 (Sat)** | Twitter Thread #11 (lessons learned) + Thread #12 (recap + CTA) | Twitter/X | 15:00 + 18:00 UTC |
| 12 | Post the repo to **Lobste.rs** and **Hacker News** (Show HN) | HN / Lobsters | 13:00–15:00 UTC (weekday better — consider moving to Day 13/Mon) |

> **HN tip:** "Show HN: Portcullis – CI/CD pipeline security scanner (GitHub, GitLab, Jenkins)" posts do best **Tue–Thu, 13:00–16:00 UTC**. If Day 12 is a weekend, hold the HN post to the next Tuesday.

## Universal posting rules (from the playbook)

- **Blogs**: publish on Hashnode first, then cross-post to Dev.to with a
  `canonical_url` pointing back to Hashnode (avoids SEO duplicate penalty).
  Submit to Medium's *InfoSec Write-ups* publication last.
- **Twitter threads**: no `1/12` numbering in the text (looks amateur); let the
  reply-chain do it. One image or code block per thread minimum. Pin Thread #1
  for the launch week. Reply to your own thread with the blog link, not the
  first tweet (protects reach).
- **LinkedIn**: put the link in the **first comment**, not the post body
  (the algorithm suppresses external links in-body). Post Tue–Thu mornings.
- **Reddit**: r/netsec wants substance, no marketing tone — lead with the
  technical finding, not "I built a tool." Read each sub's rules first.
- **Engage for 60–90 min** after every post. The first hour of replies drives
  the algorithm on every platform.

## Honesty guardrails (do not skip)

Portcullis is a defensive tool built on the inert-fixture law. When posting:

- **Never name a real repository as "vulnerable" or "exploitable."** The
  evaluation surfaced patterns at MEDIUM confidence that maintainers may have
  already accepted. Describe *pattern classes*, not accusations.
- **No fabricated stats, CVEs, or incident names.** The playbook's hook phase
  says use real breaches — cite the public, general supply-chain-attack class
  (e.g. "pipeline compromises are a documented, growing attack surface"), never
  invented specifics.
- **Acknowledge prior art** (zizmor, poutine, actionlint, the ARGUS paper)
  every time you position Portcullis. Respect wins credibility; dunking loses it.
