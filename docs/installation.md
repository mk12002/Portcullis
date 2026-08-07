# Installation

Portcullis requires **Python 3.11+** and has a single runtime dependency
(`ruamel.yaml`).

## From a checkout

```bash
git clone https://github.com/mk12002/Portcullis
cd Portcullis
pip install -e .            # editable install, exposes the `portcullis` command
portcullis version
```

## From PyPI

Once published:

```bash
pip install portcullis-scanner
```

## Development install

```bash
pip install -e ".[dev]"    # adds pytest, ruff, mypy, jsonschema
pip install -e ".[docs]"   # adds mkdocs + mkdocs-material for the docs site
```

Run the checks:

```bash
pytest                     # 175 tests
ruff check . && ruff format --check .
mypy src/portcullis
```

## Verify it works

```bash
portcullis scan examples/vulnerable-repo --format all --out ./demo-report
# → a low score with P0 findings; open demo-report/report.html
portcullis scan examples/clean-repo
# → 100/100
```

## Requirements files

`requirements.txt` (runtime) and `requirements-dev.txt` (dev + docs) mirror the
`pyproject.toml` dependency groups for tooling that expects them. `pyproject.toml`
is the canonical source of truth.
