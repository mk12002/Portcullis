# Portcullis — LinkedIn posts

Three posts, one per blog. **Put the link in the first comment, not the post
body** — LinkedIn suppresses reach on posts with external links in-body. Post
**Tuesday–Thursday, 13:00–15:00 UTC**. Engage with every comment for the first
90 minutes.

Replace `<you>` / `[LINK]` before posting.

---

## Post #1 — with Blog 2 (build story) — Launch Day 1

Your CI/CD pipeline is the most over-privileged machine in your company that nobody watches.

It holds your deploy keys. It has write access. And several times a day, it runs code written by strangers on the internet.

I built an open-source scanner to find the misconfigurations that turn that combination into a breach — then I pointed it at 66 real pipeline files from 10 well-known projects (Flask, FastAPI, GitHub's own Actions runner) to see if it survived contact with reality.

What I found:

→ It ran clean — 66 files, ~1.4 seconds, zero crashes, zero secret leaks in any output
→ It ranked well-maintained repos high and problematic ones low, with actionable findings
→ It agreed directionally with zizmor, a mature competing scanner — independent corroboration
→ And the real data caught TWO calibration bugs in my own tool, which I fixed (false criticals dropped two-thirds)

The biggest lesson: a security tool that cries wolf gets switched off. Testing on real data — not fixtures I wrote myself — is what made it trustworthy.

Full write-up, the tool, and the honest limitations are in the repo. Link in the comments 👇

#cybersecurity #devsecops #cicd #opensource #appsec

---

## Post #2 — with Blog 1 (threat education) — Day 3

You can lose every secret in your repository without a single commit ever being merged.

It's called a "pwn-request," and it's one of the most common CI/CD security mistakes in open source.

Here's the mechanism, in plain terms:

→ Your pipeline needs secrets to do its job, so it runs on a trigger that provides them
→ That same job checks out the code from an incoming pull request
→ An attacker opens a PR that replaces the build script with code that steals your secrets
→ Merely opening the PR runs it — with your credentials in the environment

The fix is architectural: untrusted pull-request code and secrets must never share a job. And a second, subtler bug — pasting an attacker-controlled PR title straight into a shell command — is defeated by one habit: route dynamic values through environment variables so the shell treats them as data, never as code.

I wrote up the full anatomy of a pipeline compromise — accessible whether or not you write YAML for a living — and built an open-source scanner (Portcullis) that catches these across GitHub Actions, GitLab CI, and Jenkins.

Link in the comments 👇

#cybersecurity #supplychainsecurity #devsecops #githubactions #infosec

---

## Post #3 — with Blog 3 (deep dive) — Day 8

Two pipeline jobs contain the identical line: `curl install.sh | bash`.

One is a hygiene note you'll get to next sprint. The other should block your merge right now.

The line is the same. What differs is who can reach it — and encoding that difference is the single design decision that separates a useful security scanner from one your team switches off in a week.

The failure mode of static analysis isn't missing bugs. It's crying wolf until nobody listens. The fix is to model context explicitly:

→ Compute, for every job, whether an attacker can supply input to it — once, at parse time
→ Escalate findings inside those reachable jobs by one severity level
→ Reserve your top "block the merge" priority for genuinely reachable criticals
→ Make confidence first-class, so uncertain findings never manufacture a false emergency

That's the load-bearing idea in Portcullis, my open-source pipeline scanner. I wrote up how it works — and why "severity is a property of a pattern in a context, not of the pattern alone" is the insight that makes the whole thing trustworthy.

Link in the comments 👇

#staticanalysis #cybersecurity #devsecops #cicd #softwareengineering
