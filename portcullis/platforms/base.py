"""Platform abstraction and shared YAML helpers.

Adding a platform = subclassing ``Platform`` and emitting the normalized
``Pipeline`` model. Parsers must never execute pipeline content and must
preserve line numbers for the evidence model (hence ruamel.yaml round-trip
loading, which annotates every node with its source position).
"""

from __future__ import annotations

import io
from abc import ABC, abstractmethod
from typing import Any

from ruamel.yaml import YAML

from portcullis.core.models import Pipeline


class ParseError(Exception):
    """Raised when a pipeline file cannot be parsed; the engine converts this
    into a warning plus a LOW finding rather than crashing the scan."""


class Platform(ABC):
    """One CI system. ``matches`` selects files; ``parse`` normalizes them."""

    name: str = ""

    @abstractmethod
    def matches(self, rel_path: str) -> bool:
        """Whether a repo-relative POSIX path is a pipeline file of this platform."""

    @abstractmethod
    def parse(self, text: str, rel_path: str) -> Pipeline:
        """Parse file content into the normalized model. Raises ParseError."""


def load_yaml(text: str, rel_path: str) -> Any:
    """Round-trip-load YAML so every node carries line/column info.

    Multi-document files: only the first document is analyzed (recorded as a
    pipeline warning by callers that care).
    """
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    try:
        docs = list(yaml.load_all(io.StringIO(text)))
    except Exception as exc:  # ruamel raises many error types
        raise ParseError(f"{rel_path}: YAML parse error: {exc}") from exc
    docs = [d for d in docs if d is not None]
    if not docs:
        raise ParseError(f"{rel_path}: empty or null YAML document")
    return docs[0]


def key_line(node: Any, key: Any, default: int = 1) -> int:
    """1-based line of ``key`` inside a ruamel mapping node."""
    try:
        return int(node.lc.data[key][0]) + 1
    except Exception:
        return node_line(node, default)


def value_line(node: Any, key: Any, default: int = 1) -> int:
    """1-based line of the *value* for ``key`` in a ruamel mapping node."""
    try:
        return int(node.lc.data[key][2]) + 1
    except Exception:
        return key_line(node, key, default)


def item_line(seq: Any, index: int, default: int = 1) -> int:
    """1-based line of a sequence item."""
    try:
        return int(seq.lc.data[index][0]) + 1
    except Exception:
        return node_line(seq, default)


def node_line(node: Any, default: int = 1) -> int:
    """1-based line of a node itself."""
    try:
        return int(node.lc.line) + 1
    except Exception:
        return default


def as_str_dict(value: Any) -> dict[str, Any]:
    """Coerce a YAML mapping into {str: scalar} without failing on odd shapes."""
    if not isinstance(value, dict):
        return {}
    return {str(k): v for k, v in value.items()}
