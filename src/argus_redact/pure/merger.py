"""merge_entities() — deduplicate overlapping entity spans from multiple layers."""

from __future__ import annotations

from argus_redact._types import PatternMatch

try:
    from argus_redact._core import merge_entities as _rust_merge

    def merge_entities(entities: list[PatternMatch]) -> list[PatternMatch]:
        """Deduplicate overlapping entity spans (Rust accelerated)."""
        if not entities:
            return []
        from argus_redact._core import PatternMatch as RustPM

        # Convert Python PatternMatch to Rust PatternMatch
        rust_entities = [
            RustPM(e.text, e.type, e.start, e.end, e.confidence, e.layer)
            for e in entities
        ]
        rust_results = _rust_merge(rust_entities)
        # Convert back
        return [
            PatternMatch(text=r.text, type=r.type, start=r.start, end=r.end,
                         confidence=r.confidence, layer=r.layer)
            for r in rust_results
        ]

except ImportError:
    def _overlaps(a: PatternMatch, b: PatternMatch) -> bool:
        return a.start < b.end and b.start < a.end

    def _span_length(e: PatternMatch) -> int:
        return e.end - e.start

    def _pick_winner(a: PatternMatch, b: PatternMatch) -> PatternMatch:
        len_a = _span_length(a)
        len_b = _span_length(b)
        if len_a != len_b:
            return a if len_a > len_b else b
        return a if a.confidence >= b.confidence else b

    def merge_entities(entities: list[PatternMatch]) -> list[PatternMatch]:
        """Deduplicate overlapping entity spans (Python fallback)."""
        if not entities:
            return []
        sorted_entities = sorted(entities, key=lambda e: (e.start, -_span_length(e)))
        merged: list[PatternMatch] = [sorted_entities[0]]
        for current in sorted_entities[1:]:
            last = merged[-1]
            if not _overlaps(last, current):
                merged.append(current)
                continue
            merged[-1] = _pick_winner(last, current)
        return merged
