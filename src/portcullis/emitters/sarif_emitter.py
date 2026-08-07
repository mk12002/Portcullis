"""SARIF 2.1.0 emitter — code-scanning-ready results with physical locations."""

from __future__ import annotations

import json

from portcullis import TOOL_NAME, __version__
from portcullis.core.models import Report, Severity
from portcullis.rules import all_rule_metas

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def emit_sarif(report: Report) -> str:
    rules = [
        {
            "id": meta.rule_id,
            "name": meta.name.replace(" ", ""),
            "shortDescription": {"text": meta.name},
            "fullDescription": {"text": meta.summary},
            "help": {"text": f"{meta.summary}\n\nFalse-positive note: {meta.fp_note}"},
        }
        for meta in all_rule_metas()
    ]
    rule_index = {r["id"]: i for i, r in enumerate(rules)}

    results = []
    for f in report.findings:
        severity = f.severity if f.severity is not None else f.base_severity
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": _LEVELS[severity],
                "message": {
                    "text": f"[{severity.name}/{f.confidence.name} confidence] {f.message} "
                    f"Remediation: {f.remediation}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": max(1, f.line)},
                        },
                        "logicalLocations": (
                            [{"name": f.job_name, "kind": "member"}] if f.job_name else []
                        ),
                    }
                ],
                "partialFingerprints": {
                    "portcullisFinding": f"{f.rule_id}:{f.kind}:{f.file_path}:{f.line}"
                },
                "properties": {
                    "kind": f.kind,
                    "priority": f.priority.name if f.priority is not None else None,
                    "confidence": f.confidence.name,
                    "untrusted_reachable": f.untrusted_reachable,
                    "escalated": f.escalated,
                },
            }
        )

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": "https://github.com/portcullis-scanner/portcullis",
                        "rules": rules,
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
