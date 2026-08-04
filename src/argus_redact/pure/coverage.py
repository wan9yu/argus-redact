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
from argus_redact._types import Hint, PatternMatch
from argus_redact.pure.hints import _get_self_reference_tier

_RustPM = _core.PatternMatch


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
    drop_self_reference = hints is not None and _get_self_reference_tier(hints) != 1
    out, restored = _core.restore_lost_coverage(
        [_RustPM(e.text, e.type, e.start, e.end, e.confidence, e.layer) for e in pre_merge],
        [(e.start, e.end) for e in merged],
        [_RustPM(e.text, e.type, e.start, e.end, e.confidence, e.layer) for e in filtered],
        types,
        types_exclude,
        drop_self_reference,
        text,
    )
    if not restored:
        return filtered, []
    return (
        [
            PatternMatch(
                text=e.text,
                type=e.type,
                start=e.start,
                end=e.end,
                confidence=e.confidence,
                layer=e.layer,
            )
            for e in out
        ],
        list(restored),
    )
