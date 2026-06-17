"""English grammar normalization/de-normalization for first-person replacement.

Thin wrapper — logic lives in the Rust core.
"""

from __future__ import annotations

import argus_redact._core as _core

# SSOT: sourced from the Rust core — not a hand-maintained copy.
SELF_REF_PRONOUNS: frozenset[str] = frozenset(_core.self_ref_pronouns())


def normalize_grammar_en(text: str, key: dict[str, str]) -> str:
    """Fix English verb forms after first-person pronoun replacement."""
    return _core.normalize_grammar_en(text, list(key.values()))


def restore_grammar_en(text: str) -> str:
    """Reverse grammar normalization after restore."""
    return _core.restore_grammar_en(text)
