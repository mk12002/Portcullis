# CLI Reference

```text
portcullis scan <path>
    --format {json,html,sarif,md,all}   default: html
    --out DIR                           default: ./portcullis-report
    --fail-on {P0,P1,P2,P3}             exit 1 if any finding is at/above this priority
    --platforms LIST                    subset of github,gitlab,jenkins
    --trusted-actions PREFIX            repeatable; treat prefix as first-party (lower R3 urgency)
    --quiet                             suppress the console summary
    -v, --verbose                       increase log verbosity (-v info, -vv debug; logs to stderr)
portcullis rules list                   print the rule catalog + false-positive notes
portcullis version
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | scan completed; nothing at/above the `--fail-on` threshold |
| `1` | findings at/above the `--fail-on` threshold (the gate tripped) |
| `2` | usage error (bad path, unknown platform) |

The exit code is the integration point: `portcullis scan . --fail-on P0` returns
`1` to fail a CI step and block a merge.

## Examples

```bash
# Scan the current repo, write an HTML report
portcullis scan .

# All four formats, gate on P0
portcullis scan . --format all --out ./report --fail-on P0

# Only GitHub Actions, treat your org's actions as first-party
portcullis scan . --platforms github --trusted-actions myorg/

# Verbose logging to stderr (does not pollute stdout / report output)
portcullis scan . -vv

# Print the rule catalog
portcullis rules list
```

## Suppressing a reviewed finding

Inline comments dismiss a finding without editing the tool — and are reported in
every output so they're never silent:

```yaml
- uses: example-org/tool@v3   # portcullis: ignore[R3]   (or bare: # portcullis: ignore)
```

`//` works for Jenkinsfiles. Place the comment on the finding's line or the line
above it.

## Logging

Portcullis logs to **stderr** (stdout is reserved for report/machine output) and
is silent by default. `-v` raises to INFO, `-vv` to DEBUG. As a library, importing
Portcullis never configures logging for the host application.
