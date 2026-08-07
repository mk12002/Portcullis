<!-- Thanks for contributing to Portcullis! -->

## What does this PR do?

<!-- A short description of the change and why. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New detection rule / rule improvement
- [ ] New platform parser
- [ ] Docs / examples
- [ ] Tooling / CI
- [ ] Other:

## Checklist

- [ ] `pytest` passes locally (and new behavior has a test)
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy src/portcullis` passes
- [ ] Every new rule `kind` has an explicit test (`test_rule_coverage_gaps.py` pattern)
- [ ] If a rule changed what fires or how it's scored, I updated `CHANGELOG.md`
- [ ] New/changed fixtures obey the **inert-fixture law** (echo payloads, `example.com`, fake secrets) and pass `test_inertness.py`
- [ ] If I touched the SARIF emitter, `test_sarif_schema.py` still passes
- [ ] I did **not** add a runtime dependency without justifying it (stdlib-first policy)

## Notes for reviewers

<!-- Anything you want a reviewer to look at closely, calibration tradeoffs, etc. -->
