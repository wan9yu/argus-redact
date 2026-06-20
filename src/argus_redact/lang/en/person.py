"""English person-name detection — thin shim over the Rust ``_core``.

Algorithm (in the Rust ``person_en`` detector): scan capitalized-word tokens,
identify those in the known surname list, then look back at 1-2 preceding
capitalized tokens (a known given name or an initial) to assemble the full person
match. A full ``Given + Surname`` (both in the pools) or a ``known_names`` match
is emitted high-confidence; a BARE surname-pool match (capitalized leading word
that is NOT a known given name) is EVIDENCE-GATED, mirroring the zh detector — it
is emitted only when a title/honorific immediately precedes the surname or the
surname is near other detected PII, otherwise it is left to L2 NER. The surname /
given-name pools (U.S. Census 2010 surnames + SSA top given names, both public
domain) are embedded as RON in the core. This module only marshals the result
across the FFI boundary.
"""

from __future__ import annotations

from argus_redact._core_loader import _core
from argus_redact._types import PatternMatch

_RustPM = _core.PatternMatch
_detect_en = _core.detect_person_names_en

# Confirmation threshold for a bare-surname candidate (mirrors the Rust core's
# SCORE_THRESHOLD and the zh shim's default). Kept as a module constant so the
# default below reads as intent rather than a bare 0.8.
_SCORE_THRESHOLD = 0.8


def detect_person_names(
    text: str,
    *,
    pii_entities: list[PatternMatch] | None = None,
    known_names: list[str] | None = None,
    threshold: float = _SCORE_THRESHOLD,
) -> list[PatternMatch]:
    """Detect English person names via surname-list match + given-name look-back.

    Args:
        text: Input text.
        pii_entities: Structural PII already detected by Layer 1 (phone, ID, etc.).
            Used as a proximity signal corroborating a bare-surname candidate;
            the ``self_reference`` filtering matches the zh detector. All fields
            are forwarded to Rust.
        known_names: User-provided names to always match (confidence=1.0).
        threshold: Minimum score to confirm a BARE-surname candidate (default
            0.8). A given-name-led or ``known_names`` match bypasses the gate.

    Returns:
        List of PatternMatch with type="person" for confirmed names. Confidence:
        - ``known_names`` exact match: 1.0
        - given-name-led (``Given + Surname``, both pooled): 1.0
        - bare surname with corroboration (title / PII-proximity): the gated
          score (``base + evidence``, <= 1.0)
        - bare surname with no corroboration: suppressed (left to L2 NER)
    """
    rust_pii = (
        [_RustPM(e.text, e.type, e.start, e.end, e.confidence, e.layer) for e in pii_entities]
        if pii_entities
        else None
    )
    return [
        PatternMatch(
            text=r.text,
            type=r.type,
            start=r.start,
            end=r.end,
            confidence=r.confidence,
            layer=r.layer,
        )
        for r in _detect_en(text, rust_pii, known_names, threshold)
    ]
