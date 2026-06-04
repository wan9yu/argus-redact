"""Namespace shape contract for argus_redact.compose.

Pinned in v0.6.7 so the architecture-layers.md §Layer 2 promise — that
this namespace exists and exports a known set of names — cannot drift
silently. Extended in v0.6.11 with the adapter-author surface
(register_pii_type / PIITypeDef / PatternMatch).
"""
from __future__ import annotations

import warnings

import pytest


def test_compose_namespace_importable():
    import argus_redact.compose  # noqa: F401


def test_compose_exports_streaming_classes():
    from argus_redact.compose import StreamingRedactor, StreamingRestorer
    from argus_redact.streaming import StreamingRedactor as SrcRedactor
    from argus_redact.streaming import StreamingRestorer as SrcRestorer
    # Sanity: compose re-exports the same objects, no rebinding
    assert StreamingRedactor is SrcRedactor
    assert StreamingRestorer is SrcRestorer
    # StreamingRedactor (only) is also top-level for backwards compat (v0.6.10
    # emits DeprecationWarning here; removal deferred to v1.0). The warning
    # contract itself is exercised in tests/test_top_level_deprecation.py.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from argus_redact import StreamingRedactor as TopRedactor
    assert StreamingRedactor is TopRedactor


def test_compose_exports_redact_pseudonym_llm():
    from argus_redact import redact_pseudonym_llm as top_alias
    from argus_redact.compose import redact_pseudonym_llm
    assert redact_pseudonym_llm is top_alias


def test_prompt_anchor_real_returns_addendum():
    """v0.6.9: prompt_anchor ships real implementation (was stub in v0.6.7-0.6.8)."""
    from argus_redact.compose import prompt_anchor
    result = prompt_anchor({"P-001": "黄芳"}, lang="zh")
    assert result  # non-empty
    assert "P-001" in result


def test_expand_aliases_real_returns_expanded_dict():
    """v0.6.9: expand_aliases ships real implementation (was stub in v0.6.7-0.6.8)."""
    from argus_redact.compose import expand_aliases
    result = expand_aliases({"P-001": "黄芳"}, lang="zh")
    assert "P-001" in result and result["P-001"] == "黄芳"
    assert "黄先生" in result and result["黄先生"] == "黄芳"


def test_compose_dunder_all_is_exactly_eight():
    """Lock the namespace surface — any addition is intentional, not accidental.

    v0.6.7 baseline: 5 names. v0.6.11 added the adapter-author trio
    (register_pii_type / PIITypeDef / PatternMatch).
    """
    import argus_redact.compose as mod
    expected = {
        "StreamingRedactor",
        "StreamingRestorer",
        "redact_pseudonym_llm",
        "prompt_anchor",
        "expand_aliases",
        # v0.6.11 adapter surface
        "register_pii_type",
        "PIITypeDef",
        "PatternMatch",
    }
    assert set(mod.__all__) == expected
