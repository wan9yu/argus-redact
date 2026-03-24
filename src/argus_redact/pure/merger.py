"""merge_entities() — deduplicate overlapping entity spans from multiple layers."""

from __future__ import annotations

from argus_redact._types import PatternMatch


def _overlaps(a: PatternMatch, b: PatternMatch) -> bool:
    """Check if two spans overlap (share at least one character position)."""
    return a.start < b.end and b.start < a.end


def _contains(outer: PatternMatch, inner: PatternMatch) -> bool:
    """Check if outer fully contains inner."""
    return outer.start <= inner.start and inner.end <= outer.end


def _span_length(e: PatternMatch) -> int:
    return e.end - e.start


def _pick_winner(a: PatternMatch, b: PatternMatch) -> PatternMatch:
    """Given two overlapping entities, pick the one to keep.

    Rules:
    1. If one contains the other, keep the longer (outer) span.
    2. If partial overlap, keep the longer span.
    3. If same length, keep the higher confidence.
    """
    len_a = _span_length(a)
    len_b = _span_length(b)

    # Containment: keep the longer (outer) span
    if _contains(a, b) and len_a > len_b:
        return a
    if _contains(b, a) and len_b > len_a:
        return b

    # Same span or partial overlap with different lengths: longer wins
    if len_a != len_b:
        return a if len_a > len_b else b

    # Same length (including exact overlap): higher confidence wins
    return a if a.confidence >= b.confidence else b


def merge_entities(entities: list[PatternMatch]) -> list[PatternMatch]:
    """Deduplicate overlapping entity spans.

    Returns a sorted list of non-overlapping entities.
    """
    if not entities:
        return []

    # Sort by start position, then by span length descending (longer first)
    sorted_entities = sorted(entities, key=lambda e: (e.start, -_span_length(e)))

    merged: list[PatternMatch] = [sorted_entities[0]]

    for current in sorted_entities[1:]:
        last = merged[-1]

        if not _overlaps(last, current):
            merged.append(current)
            continue

        # Overlapping: pick winner, replace last
        winner = _pick_winner(last, current)
        merged[-1] = winner

    return merged
