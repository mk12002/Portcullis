"""Model determinism: stable sort under shuffle."""

from __future__ import annotations

import random

from portcullis.core import risk
from portcullis.core.models import Confidence, Finding, Severity


def _findings() -> list[Finding]:
    out = []
    for i in range(20):
        out.append(
            Finding(
                rule_id=f"R{(i % 6) + 1}",
                kind=f"kind-{i % 4}",
                message=f"m{i}",
                remediation="fix",
                file_path=f"f{i % 3}.yml",
                line=i,
                key_path="",
                base_severity=list(Severity)[i % 5],
                confidence=list(Confidence)[i % 3],
                job_name=f"job{i % 2}",
                untrusted_reachable=(i % 2 == 0),
            )
        )
    return out


def test_sort_deterministic_under_shuffle():
    baseline = risk.assess(_findings())
    baseline_keys = [f.sort_key() for f in baseline]
    for seed in (0, 1, 42):
        fresh = _findings()
        random.Random(seed).shuffle(fresh)
        assessed = risk.assess(fresh)
        assert [f.sort_key() for f in assessed] == baseline_keys


def test_priority_orders_before_file():
    ordered = risk.assess(_findings())
    priorities = [f.priority.value for f in ordered]
    assert priorities == sorted(priorities)
