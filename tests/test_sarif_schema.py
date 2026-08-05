"""Validate the SARIF emitter output against the official SARIF 2.1.0 schema.

Chapter 19 of the handbook (and the README) claim SARIF 2.1.0 compliance; this
test proves it against the real OASIS schema rather than trusting a hand-rolled
structural check. The schema is vendored at tests/schema/sarif-2.1.0.json.
`jsonschema` is a dev-only dependency; the test skips cleanly without it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import scan_fixture

from portcullis.emitters import emit_sarif

jsonschema = pytest.importorskip("jsonschema")

SCHEMA_PATH = Path(__file__).parent / "schema" / "sarif-2.1.0.json"


def _schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("fixture", ["github", "gitlab", "jenkins", "clean"])
def test_sarif_validates_against_official_schema(fixture):
    sarif = json.loads(emit_sarif(scan_fixture(fixture)))
    # raises jsonschema.ValidationError if the output is not spec-compliant
    jsonschema.validate(instance=sarif, schema=_schema())


def test_sarif_schema_is_the_2_1_0_schema():
    schema = _schema()
    assert "sarif-schema-2.1.0" in schema.get("$id", "")
