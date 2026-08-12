"""Chinese person-name detection — thin shim over the Rust ``_core``.

Detection is candidate generation + evidence scoring: surname (1 char, or a
2-char compound like 欧阳/司马) + 1-2 CJK chars, filtered by a negative
dictionary, then scored against weak signals (PII proximity, context-prefix /
honorific-suffix words, name length) and thresholded. That whole pipeline —
plus the surname / negative-dictionary / common-word pools (embedded as RON) —
now lives in the Rust core. This module only marshals Python ``PatternMatch``
objects across the FFI boundary; the behavior is the Rust ``person_zh``
detector, verified bit-identical to the former pure-Python implementation.
"""

from __future__ import annotations

from argus_redact._core_loader import _core
from argus_redact._types import PatternMatch
from argus_redact.lang.shared.person import detect_person

_detect_zh = _core.detect_person_names_zh

# Confirmation threshold (mirrors the Rust core's SCORE_THRESHOLD). Kept as a
# module constant so the default below reads as intent rather than a bare 0.8.
_SCORE_THRESHOLD = 0.8


def detect_person_names(
    text: str,
    *,
    pii_entities: list[PatternMatch] | None = None,
    known_names: list[str] | None = None,
    threshold: float = _SCORE_THRESHOLD,
) -> list[PatternMatch]:
    """Detect Chinese person names via candidate generation + evidence scoring.

    Args:
        text: Input text.
        pii_entities: Structural PII already detected by Layer 1 (phone, ID, etc.).
            Used as a proximity signal — names near PII score higher. The
            ``type`` field is read too (``self_reference`` entities are filtered
            out before proximity scoring), so all fields are forwarded to Rust.
        known_names: User-provided names to always match (confidence=1.0).
            Bypasses candidate generation and scoring entirely.
        threshold: Minimum score to confirm a candidate (default 0.8).

    Returns:
        List of PatternMatch with type="person" for confirmed names.
    """
    return detect_person(
        _detect_zh,
        text,
        pii_entities=pii_entities,
        known_names=known_names,
        threshold=threshold,
    )
