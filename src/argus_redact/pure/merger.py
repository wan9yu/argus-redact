"""merge_entities() — deduplicate overlapping entity spans (Rust, priority-aware).

The priority-split logic (a ``self_reference`` span wins overlaps and splits the
loser via a text-driven trim) lives in ``argus-redact-core::merger``
(``merge_entities_with_text``); this is a thin shim. The frozen API (signature +
behavior) is locked by ``tests/core/test_merge.py``.
"""

from __future__ import annotations

from argus_redact._core_loader import _core
from argus_redact._types import PatternMatch

_RustPM = _core.PatternMatch


def merge_entities(entities: list[PatternMatch], text: str = "") -> list[PatternMatch]:
    """Deduplicate overlapping entity spans (priority-aware, text-driven trim)."""
    if not entities:
        return []
    rust_entities = [
        _RustPM(e.text, e.type, e.start, e.end, e.confidence, e.layer) for e in entities
    ]
    rust_results = _core.merge_entities_with_text(rust_entities, text)
    return [
        PatternMatch(
            text=r.text,
            type=r.type,
            start=r.start,
            end=r.end,
            confidence=r.confidence,
            layer=r.layer,
        )
        for r in rust_results
    ]
