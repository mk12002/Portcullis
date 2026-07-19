"""Detection rules R1–R6, written once against the normalized Pipeline model."""

from portcullis.core.models import RuleMeta
from portcullis.rules import injection, integrity, permissions, pinning, secrets, triggers

ALL_RULE_MODULES = [triggers, injection, pinning, permissions, secrets, integrity]

# R0 is emitted by the engine itself for unparseable pipeline files.
PARSE_RULE = RuleMeta(
    rule_id="R0",
    name="Unparseable pipeline file",
    summary=(
        "A pipeline file that could not be parsed. A malformed workflow is "
        "itself a (LOW) finding: it may silently not run, and it hides from "
        "analysis."
    ),
    fp_note="Non-pipeline files matching pipeline names (e.g. templates) can trip this.",
)


def all_rule_metas() -> list[RuleMeta]:
    metas = [meta for module in ALL_RULE_MODULES for meta in module.RULES]
    metas.append(PARSE_RULE)
    return sorted(metas, key=lambda m: m.rule_id)
