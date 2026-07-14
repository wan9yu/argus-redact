"""English grammar normalization/de-normalization for first-person replacement.

Thin wrapper — logic lives in the Rust core.
"""

from __future__ import annotations

import argus_redact._core as _core

# SSOT: sourced from the Rust core — not a hand-maintained copy.
SELF_REF_PRONOUNS: frozenset[str] = frozenset(_core.self_ref_pronouns())


def normalize_grammar_en(text: str, originals: list[str]) -> str:
    """Fix English verb forms after first-person pronoun replacement.

    ``originals`` is the list of replaced original values to normalize around.
    Callers with a key dict pass ``list(key.values())``; the structured per-cell
    path passes just that cell's originals (the cumulative key's extras are no-ops
    on this cell's text, so passing them would only re-marshal a growing key)."""
    return _core.normalize_grammar_en(text, originals)


def restore_grammar_en(text: str) -> str:
    """Reverse grammar normalization after restore."""
    return _core.restore_grammar_en(text)
