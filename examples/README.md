# Examples

Copy-paste, runnable examples for Portcullis. Install first:

```bash
pip install -e .          # from a checkout
# or, once published:  pip install portcullis-scanner
```

## 1. Scan a deliberately-vulnerable repo

[`vulnerable-repo/`](vulnerable-repo/) is a tiny repo whose workflow is genuinely
misconfigured (a pwn-request + expression injection) — but **inert** (echo
payloads, `example.com`, fake secrets). Scan it:

```bash
portcullis scan examples/vulnerable-repo --format all --out ./demo-report
```

You'll see a low score and P0 findings. Open `demo-report/report.html`.

## 2. Scan a secure repo

[`clean-repo/`](clean-repo/) is the same workflow done right (SHA-pinned,
least-privilege, untrusted input routed through `env:`). It scores 100/100:

```bash
portcullis scan examples/clean-repo
```

## 3. Use Portcullis as a Python library

[`python_api.py`](python_api.py) scans a path programmatically and prints the
findings — useful for building your own integrations.

```bash
python examples/python_api.py examples/vulnerable-repo
```

## 4. Add Portcullis as a CI merge gate

[`portcullis-gate.yml`](portcullis-gate.yml) is a copy-paste GitHub Actions job
that fails the build on any P0 finding. Drop it into your own
`.github/workflows/`.

## The inert-example rule

Every vulnerable example here follows the same law as the test fixtures:
vulnerable-looking, harmless-acting. Payloads are `echo`, URLs are `example.com`,
"secrets" are obviously fake. These demonstrate the vulnerability classes without
being weapons.
