"""English grammar normalization/de-normalization for first-person replacement.

Thin wrapper — logic lives in the Rust core.
"""

from __future__ import annotations

import argus_redact._core as _core

# Re-exported for importers (pure/replacer.py, pure/restore.py). Mirrors the Rust
# `grammar::SELF_REF_PRONOUNS` const — kept in sync by hand for now.
# TODO(v0.7.4 cleanup): vestigial once replacer/restore move to Rust; remove this
# Python copy then and source the set from `_core`.
SELF_REF_PRONOUNS: frozenset[str] = frozenset(
    {
        "I", "me", "my", "mine", "myself",
        "we", "us", "our", "ours", "ourselves",
    }
)


def normalize_grammar_en(text: str, key: dict[str, str]) -> str:
    """Fix English verb forms after first-person pronoun replacement."""
    return _core.normalize_grammar_en(text, list(key.values()))


def restore_grammar_en(text: str) -> str:
    """Reverse grammar normalization after restore."""
    return _core.restore_grammar_en(text)
