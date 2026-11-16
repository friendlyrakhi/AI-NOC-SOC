"""Input limits for untrusted payloads (threat model T13, T15)."""

from typing import Any

MAX_DEPTH = 32
MAX_RECORD_BYTES = 262_144  # one normalized-input record (envelope ``data``)


def json_depth(value: Any, limit: int = MAX_DEPTH) -> int:
    """Nesting depth, computed iteratively; stops counting once ``limit`` is exceeded."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > deepest:
            deepest = depth
            if deepest > limit:
                return deepest
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
    return deepest
