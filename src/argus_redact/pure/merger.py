"""merge_entities() — deduplicate overlapping entity spans from multiple layers."""

from __future__ import annotations

from argus_redact._types import PatternMatch

_PRIORITY_TYPES = frozenset({"self_reference"})


def _trim_entity(e: PatternMatch, new_start: int, text: str) -> PatternMatch | None:
    """Trim entity to start after new_start, return None if nothing left."""
    if new_start >= e.end:
        return None
    new_text = text[new_start : e.end]
    if not new_text.strip():
        return None
    return PatternMatch(
        text=new_text,
        type=e.type,
        start=new_start,
        end=e.end,
        confidence=e.confidence,
        layer=e.layer,
    )


def _merge_priority(
    merged_others: list[PatternMatch],
    priority: list[PatternMatch],
    text: str,
) -> list[PatternMatch]:
    """Insert priority entities into merged results, splitting overlaps."""
    all_entities = merged_others + priority
    all_entities.sort(key=lambda e: (e.start, -(e.end - e.start)))
    final: list[PatternMatch] = [all_entities[0]]
    for current in all_entities[1:]:
        last = final[-1]
        if current.start >= last.end:
            final.append(current)
            continue
        # Overlap — priority wins
        if current.type in _PRIORITY_TYPES and last.type not in _PRIORITY_TYPES:
            trimmed = _trim_entity(last, current.end, text) if text else None
            final[-1] = current
            if trimmed:
                final.append(trimmed)
        elif last.type in _PRIORITY_TYPES and current.type not in _PRIORITY_TYPES:
            trimmed = _trim_entity(current, last.end, text) if text else None
            if trimmed:
                final.append(trimmed)
        else:
            if (current.end - current.start) > (last.end - last.start):
                final[-1] = current
            elif current.confidence > last.confidence:
                final[-1] = current
    final.sort(key=lambda e: e.start)
    return final


try:
    from argus_redact._core import merge_entities as _rust_merge

    def merge_entities(
        entities: list[PatternMatch],
        text: str = "",
    ) -> list[PatternMatch]:
        """Deduplicate overlapping entity spans (Rust accelerated + priority split)."""
        if not entities:
            return []

        # Short-circuit: no priority entities → pure Rust path
        has_priority = any(e.type in _PRIORITY_TYPES for e in entities)
        if not has_priority:
            from argus_redact._core import PatternMatch as RustPM

            rust_entities = [
                RustPM(e.text, e.type, e.start, e.end, e.confidence, e.layer) for e in entities
            ]
            rust_results = _rust_merge(rust_entities)
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

        # Has priority entities: merge others with Rust, then priority-split in Python
        from argus_redact._core import PatternMatch as RustPM

        others = [e for e in entities if e.type not in _PRIORITY_TYPES]
        priority = [e for e in entities if e.type in _PRIORITY_TYPES]

        if others:
            rust_entities = [
                RustPM(e.text, e.type, e.start, e.end, e.confidence, e.layer) for e in others
            ]
            rust_results = _rust_merge(rust_entities)
            merged_others = [
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
        else:
            merged_others = []

        return _merge_priority(merged_others, priority, text)

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

    def merge_entities(
        entities: list[PatternMatch],
        text: str = "",
    ) -> list[PatternMatch]:
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

            if current.type in _PRIORITY_TYPES and last.type not in _PRIORITY_TYPES:
                trimmed = _trim_entity(last, current.end, text) if text else None
                merged[-1] = current
                if trimmed:
                    merged.append(trimmed)
                continue
            if last.type in _PRIORITY_TYPES and current.type not in _PRIORITY_TYPES:
                trimmed = _trim_entity(current, last.end, text) if text else None
                if trimmed:
                    merged.append(trimmed)
                continue

            merged[-1] = _pick_winner(last, current)
        return merged
