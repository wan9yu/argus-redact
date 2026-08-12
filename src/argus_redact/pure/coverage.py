"""Post-merge coverage invariant — the Python face of the shared core primitive.

The detection pipeline ends with a priority-aware merge followed by dropping
filters. The merge is absorbing: an overlapping loser is discarded because the
winner covers its bytes. A filter that then drops a winner un-covers everything
that winner absorbed. This restores that coverage.

The predicate lives in Rust (`argus_redact_core::coverage::FilterScope`) so the
filters and the restorer cannot drift apart; this module only marshals.
"""

from __future__ import annotations

from argus_redact._core_loader import _core
from argus_redact._types import Hint, PatternMatch, from_rust_pm, to_rust_pm
from argus_redact.pure.hints import _get_self_reference_tier


def restore_lost_coverage(
    pre_merge: list[PatternMatch],
    merged: list[PatternMatch],
    filtered: list[PatternMatch],
    *,
    types: list[str] | None,
    types_exclude: list[str] | None,
    hints: list[Hint] | None,
    text: str,
) -> tuple[list[PatternMatch], list[str]]:
    """Re-admit entities whose coverage a post-merge filter destroyed.

    ``hints`` is the hint list when ``filter_self_reference`` ran on this path,
    and ``None`` when it did not (the ``_pre_detected`` branch runs merge + type
    filter only). The distinction matters: an EMPTY hint list means "tier absent",
    which is a drop-all tier, whereas ``None`` means the filter never ran and no
    ``self_reference`` entity was dropped.

    Returns ``(entities, restored_types)``. ``restored_types`` is sorted,
    deduplicated and PII-free (type names only), empty when nothing was lost.
    """
    if not pre_merge:
        return filtered, []
    # Fast path: with no type filter and no self_reference entity anywhere in
    # pre_merge, neither `_apply_type_filter` nor `filter_self_reference` could
    # have dropped anything (the former is an identity transform when both
    # `types` and `types_exclude` are None; the latter only ever drops entities
    # typed exactly "self_reference", and merge never invents that type on an
    # entity that wasn't already present pre-merge) — `filtered` already equals
    # `merged`, so skip the PatternMatch round-trip into Rust entirely.
    if (
        types is None
        and types_exclude is None
        and not any(e.type == "self_reference" for e in pre_merge)
    ):
        return filtered, []
    # Second fast path, O(1), for the type-filtered callers the check above lets
    # through: both post-merge filters only ever REMOVE entities, never add or
    # replace, so an unchanged length means nothing was dropped — and coverage
    # can only be lost by a drop. This is a length comparison, not a second
    # implementation of the coverage predicate: reimplementing that in Python is
    # exactly the drift this module exists to prevent.
    if len(filtered) == len(merged):
        return filtered, []
    drop_self_reference = hints is not None and _get_self_reference_tier(hints) != 1
    out, restored = _core.restore_lost_coverage(
        [to_rust_pm(e) for e in pre_merge],
        [(e.start, e.end) for e in merged],
        [to_rust_pm(e) for e in filtered],
        types,
        types_exclude,
        drop_self_reference,
        text,
    )
    if not restored:
        return filtered, []
    return (
        [from_rust_pm(e) for e in out],
        list(restored),
    )
