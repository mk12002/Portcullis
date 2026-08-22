# Releasing Portcullis (+ getting a citable DOI)

This is the runbook for cutting a release, publishing to PyPI, and archiving the
release on Zenodo to mint a **DOI** so the project is formally citable. Steps
marked **[you]** require your accounts/credentials and cannot be automated from
the repo; steps marked **[repo]** are already wired up here.

## 0. Pre-flight (green build)

```bash
pip install -e ".[dev]"
pytest                       # 175 tests
ruff check . && ruff format --check .
mypy src/portcullis
python -m build && twine check dist/*   # package + metadata valid
```

All must pass. The CI workflow enforces the same on every push.

## 1. Bump the version **[repo → you commit]**

Update the version in **one** place and let it flow:

- `pyproject.toml` → `version = "0.1.0"`
- `src/portcullis/__init__.py` → `__version__ = "0.1.0"`
- `CITATION.cff` → `version:` and `date-released:`
- Add a dated section to `CHANGELOG.md`.

Keep them identical. (Pre-1.0 is correct for a first release — don't jump to
1.0; see the versioning note in the handbook / CHANGELOG.)

## 2. Tag and push **[you]**

```bash
git commit -am "release: v0.1.0"
git tag -a v0.1.0 -m "Portcullis v0.1.0"
git push origin main --tags
```

Pushing the tag triggers `.github/workflows/release.yml`, which builds the
sdist+wheel, runs `twine check`, publishes to PyPI (if `PYPI_API_TOKEN` is set),
and creates a GitHub Release with auto-generated notes.

## 3. PyPI **[you, one-time setup]**

Either:
- add a `PYPI_API_TOKEN` repository secret (from <https://pypi.org/manage/account/token/>), **or**
- switch the release workflow to **Trusted Publishing** (OIDC) — no stored token
  (recommended; see <https://docs.pypi.org/trusted-publishers/>).

After the first publish: `pip install portcullis-scanner` works for anyone.

## 4. Zenodo DOI **[you, one-time setup + per-release]**

This is the single highest-leverage credibility step and turns "here's a GitHub
URL" into "here's a citable, archived artifact with a DOI."

**One-time:**
1. Sign in to <https://zenodo.org> with GitHub.
2. Go to Zenodo → **GitHub** settings, find `mk12002/Portcullis`, flip the
   toggle **On**. (Docs: GitHub's "Referencing and citing content" /
   "making-your-code-citable" guide, and Zenodo's GitHub integration.)

**Per release:**
3. Create the GitHub Release (step 2 does this automatically on tag push, or do
   it manually). Zenodo detects the release, archives the source, and mints a
   **DOI** using the metadata in `CITATION.cff`.
4. Copy the DOI badge Markdown from the Zenodo record.

**Then update the README badge** — replace the placeholder in `README.md`:

```markdown
[![DOI](https://zenodo.org/badge/DOICODE.svg)](https://doi.org/10.5281/zenodo.XXXXXXX)
```

Zenodo issues a **version DOI** per release and a **concept DOI** that always
points to the latest — cite the concept DOI in papers.

## 5. Docs site **[you, one-time]**

`.github/workflows/docs.yml` deploys the MkDocs site to GitHub Pages on push to
`main`. Enable it once: repo **Settings → Pages → Source: GitHub Actions** (or
`gh-pages` branch). Then the site is live at
`https://mk12002.github.io/Portcullis/`.

## Release checklist

- [ ] Green build (tests, lint, format, types, `twine check`)
- [ ] Version bumped in pyproject / `__init__` / CITATION / CHANGELOG (identical)
- [ ] Tag pushed → release workflow ran
- [ ] PyPI publish succeeded (`pip install portcullis-scanner`)
- [ ] Zenodo minted a DOI → README badge updated
- [ ] Docs site deployed
