"""Tests for the per-lang hints registry — kinship + command-mode detection."""

from argus_redact._types import PatternMatch
from argus_redact.pure.hints import (
    _is_interaction_command,
    _is_kinship,
)


def _self_ref(text: str) -> PatternMatch:
    return PatternMatch(
        text=text, type="self_reference", start=0, end=len(text), confidence=1.0, layer=1
    )


class TestKinshipLookup:
    def test_zh_kinship_exact_match(self):
        assert _is_kinship(_self_ref("我妈妈"))
        assert _is_kinship(_self_ref("我家人"))

    def test_en_kinship_prefix_match(self):
        assert _is_kinship(_self_ref("my mother"))
        assert _is_kinship(_self_ref("my brother"))

    def test_unknown_text_is_not_kinship(self):
        assert not _is_kinship(_self_ref("我"))
        assert not _is_kinship(_self_ref("hello world"))


class TestCommandLookup:
    def test_zh_command_prefix(self):
        assert _is_interaction_command("帮我查一下电话号码")
        assert _is_interaction_command("我想知道这个人的地址")

    def test_en_command_pattern(self):
        assert _is_interaction_command("Can you help me find my passport?")
        assert _is_interaction_command("Please tell me the phone number.")

    def test_narrative_text_is_not_command(self):
        assert not _is_interaction_command("张明今天去了北京")
        assert not _is_interaction_command("The meeting was held in Tokyo.")
