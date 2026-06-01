"""Namespace shape contract for argus_redact.compose.

Pinned in v0.6.7 so the architecture-layers.md §Layer 2 promise — that
this namespace exists and exports these 5 names — cannot drift silently.
"""
from __future__ import annotations

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
    # StreamingRedactor (only) is also top-level for backwards compat
    from argus_redact import StreamingRedactor as TopRedactor
    assert StreamingRedactor is TopRedactor


def test_compose_exports_redact_pseudonym_llm():
    from argus_redact import redact_pseudonym_llm as top_alias
    from argus_redact.compose import redact_pseudonym_llm
    assert redact_pseudonym_llm is top_alias


def test_prompt_anchor_stub_raises_with_roadmap_hint():
    from argus_redact.compose import prompt_anchor
    with pytest.raises(NotImplementedError, match="v0.6.9"):
        prompt_anchor({"P-001": "黄芳"}, lang="zh")


def test_expand_aliases_stub_raises_with_roadmap_hint():
    from argus_redact.compose import expand_aliases
    with pytest.raises(NotImplementedError, match="v0.6.9"):
        expand_aliases({"P-001": "黄芳"}, lang="zh")


def test_compose_dunder_all_is_exactly_five():
    """Lock the namespace surface — any addition is intentional, not accidental."""
    import argus_redact.compose as mod
    expected = {
        "StreamingRedactor",
        "StreamingRestorer",
        "redact_pseudonym_llm",
        "prompt_anchor",
        "expand_aliases",
    }
    assert set(mod.__all__) == expected
