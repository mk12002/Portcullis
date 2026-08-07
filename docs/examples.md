# Examples

Runnable examples live in the [`examples/`](https://github.com/mk12002/Portcullis/tree/main/examples)
folder.

## Scan a vulnerable repo

```bash
portcullis scan examples/vulnerable-repo --format all --out ./demo-report
```

`examples/vulnerable-repo` contains an inert-but-vulnerable workflow (a
pwn-request plus expression injection). Expect a low score and P0 findings.
Open `demo-report/report.html`.

## Scan a secure repo

```bash
portcullis scan examples/clean-repo
```

The same task done right — SHA-pinned, least-privilege, untrusted input routed
through `env:`. Scores 100/100.

## Programmatic use

```bash
python examples/python_api.py examples/vulnerable-repo
```

See the [Python API](api.md) page.

## Add Portcullis as a CI gate

`examples/portcullis-gate.yml` is a copy-paste GitHub Actions job that fails the
build on any P0 finding:

```yaml
- name: scan pipelines (fail on P0)
  run: |
    pip install portcullis-scanner
    portcullis scan . --format sarif --out ./portcullis-report --fail-on P0
```

## The inert-example rule

Every vulnerable example is **vulnerable-looking, harmless-acting**: `echo`
payloads, `example.com` URLs, obviously-fake secret strings. They demonstrate
the vulnerability classes without shipping working attacks.
