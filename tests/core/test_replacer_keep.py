"""Tests for the v0.5.7 `keep` strategy.

`keep` detects an entity (so it shows up in stats / hints / risk) but
preserves the original text in the output and does not mint a key entry.
Used by self_reference's new default; also available via strategy_overrides.
"""

import pytest

from argus_redact._types import PatternMatch
from argus_redact.pure.replacer import VALID_STRATEGIES, replace


def _entity(text: str, ent_type: str, start: int, end: int) -> PatternMatch:
    return PatternMatch(text=text, type=ent_type, start=start, end=end, confidence=1.0, layer=1)


class TestKeepStrategyValidation:
    def test_keep_is_in_valid_strategies(self):
        assert "keep" in VALID_STRATEGIES


class TestKeepStrategyPreservesText:
    def test_keep_strategy_does_not_replace_text(self):
        text = "phone 13912345678"
        entities = [_entity("13912345678", "phone", 6, 17)]
        config = {"phone": {"strategy": "keep"}}

        redacted, key = replace(text, entities, config=config)

        assert redacted == text, f"text should be untouched, got {redacted!r}"

    def test_keep_strategy_no_key_entry(self):
        text = "phone 13912345678"
        entities = [_entity("13912345678", "phone", 6, 17)]
        config = {"phone": {"strategy": "keep"}}

        _, key = replace(text, entities, config=config)

        assert "13912345678" not in key.values(), "kept entity should not appear in key dict"


class TestKeepStrategyMixed:
    def test_keep_only_one_type_others_redacted(self):
        text = "我叫张伟, 电话13800138000"
        entities = [
            _entity("我", "self_reference", 0, 1),
            _entity("张伟", "person", 2, 4),
            _entity("13800138000", "phone", 8, 19),
        ]
        config = {
            "self_reference": {"strategy": "keep"},
            # person + phone go through default strategies
        }

        redacted, key = replace(text, entities, config=config)

        # self-reference '我' preserved
        assert "我叫" in redacted, f"pronoun should be preserved, got {redacted!r}"
        # phone got masked
        assert "13800138000" not in redacted, f"phone should be redacted, got {redacted!r}"
        # person got pseudonym
        assert "张伟" not in redacted, f"person should be redacted, got {redacted!r}"
        # No key entry for '我'
        assert "我" not in key.values(), "kept self_reference should not be in key dict"


class TestKeepStrategyViaOverrides:
    def test_keep_via_strategy_overrides(self):
        # strategy_overrides feeds into config["<type>"]["strategy"] inside
        # redact_pseudonym_llm — direct replace() with config simulates that.
        text = "phone 13912345678 ssn 123-45-6789"
        entities = [
            _entity("13912345678", "phone", 6, 17),
            _entity("123-45-6789", "ssn", 22, 33),
        ]
        config = {
            "phone": {"strategy": "keep"},
            "ssn": {"strategy": "remove"},
        }

        redacted, key = replace(text, entities, config=config)

        assert "13912345678" in redacted, "phone (keep) should be preserved"
        assert "123-45-6789" not in redacted, "ssn (remove) should be replaced"


class TestInvalidStrategyStillRejects:
    def test_unknown_strategy_still_raises(self):
        text = "phone 13912345678"
        entities = [_entity("13912345678", "phone", 6, 17)]
        config = {"phone": {"strategy": "bogus"}}

        with pytest.raises(ValueError) as exc:
            replace(text, entities, config=config)
        assert "Unknown strategy" in str(exc.value)
        assert "keep" in str(exc.value), "error message should list 'keep' as valid"
