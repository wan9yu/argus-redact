"""Tests unique to the v0.5.7 keep-by-default change for self_reference.

End-to-end tier behavior is covered by ``test_redact.py::TestRedactSelfReference``;
this file holds the assertions that don't fit there: the global default value,
the issue #12 verbatim repro, and the invariant that hints still fire when no
replacement happens.
"""

from argus_redact import redact
from argus_redact._types import PatternMatch
from argus_redact.pure.hints import produce_hints
from argus_redact.pure.replacer import DEFAULT_STRATEGIES


def test_self_reference_default_strategy_is_keep():
    assert DEFAULT_STRATEGIES["self_reference"] == "keep"


def test_issue_12_self_reference_verbatim_repro():
    """Issue #12 input — the pronoun part stays preserved through the full pipeline."""
    text = "我叫张伟, 手机 13800138000. 请原样复述我的姓名和手机号码"
    redacted, _ = redact(text, mode="fast", lang="zh", seed=42)
    assert "我叫" in redacted
    assert "我的" in redacted


def test_self_reference_still_emits_tier_hint_under_keep():
    # Even though self_reference text is no longer replaced, detection upstream
    # still produces an entity, so produce_hints() still emits the tier hint.
    entities = [
        PatternMatch(text="我", type="self_reference", start=0, end=1, confidence=1.0, layer=1),
    ]
    hints = produce_hints(entities, "我今天很开心")
    assert any(h.type == "self_reference_tier" for h in hints), (
        "self_reference_tier hint must still fire under keep strategy"
    )
