# Security Policy

Portcullis is a defensive security tool that parses untrusted pipeline files. We
take the security of the tool itself seriously — see [`docs/threat-model/overview.md`](docs/threat-model/overview.md)
for the tool's own threat model (it never executes pipeline content, performs no
network access at scan time, redacts detected secrets, and is hardened against
YAML alias bombs, oversized files, symlink traversal, and report XSS).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

Portcullis is pre-1.0; the latest released `0.1.x` is supported.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's **[Security Advisories](https://github.com/mk12002/Portcullis/security/advisories/new)**
("Report a vulnerability"). If you cannot use that, open a minimal public issue
asking a maintainer to contact you privately — do not include exploit details.

Please include:

- affected version / commit,
- a description of the issue and its impact,
- a minimal reproduction (an **inert** proof-of-concept — see below),
- any suggested remediation.

We aim to acknowledge reports within **5 business days** and to provide a fix or
mitigation timeline after triage.

## Scope

In scope — vulnerabilities in Portcullis itself, for example:

- a crafted pipeline file that causes a crash, hang, or resource exhaustion
  (denial of service) despite the parser hardening;
- a way to make the scanner read files outside the scan root, or perform network
  access at scan time;
- injection into a generated report (HTML/SARIF/Markdown) that executes when
  viewed;
- a detected secret leaking un-redacted into any output format.

Out of scope — findings *about scanned pipelines* (that's the product working),
and false positives/negatives (please file those as normal issues).

## Responsible-testing note

Portcullis is built on the **inert-fixture law**: demonstrate a class of issue
without shipping a working weapon. When reporting, keep proofs-of-concept inert
(harmless `echo` payloads, `example.com` URLs, obviously-fake secret strings).
Never include a functional exploit or a real credential in a report.
