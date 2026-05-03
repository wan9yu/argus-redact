"""Tests for the ``keep`` strategy contract.

v0.5.7 introduced ``keep`` for self_reference's default. v0.6.1 restricts it
to a whitelist of self-reference pronouns + kinship phrases (audit H6); any
other use downgrades to the type's default with a SecurityWarning so a
sensitive value misclassified as ``self_reference`` (or a config foot-gun
setting ``keep`` on phone/id_number/etc.) cannot leak the original.
"""

import warnings

import pytest

from argus_redact._types import PatternMatch
from argus_redact.pure.replacer import VALID_STRATEGIES, replace


def _entity(text: str, ent_type: str, start: int, end: int) -> PatternMatch:
    return PatternMatch(text=text, type=ent_type, start=start, end=end, confidence=1.0, layer=1)


class TestKeepStrategyValidation:
    def test_keep_is_in_valid_strategies(self):
        assert "keep" in VALID_STRATEGIES


class TestKeepDowngradesForNonSelfReferenceType:
    """v0.6.1: ``keep`` on phone / ssn / id_number is a footgun — downgrade."""

    def test_keep_on_phone_downgrades_and_warns(self):
        text = "phone 13912345678"
        entities = [_entity("13912345678", "phone", 6, 17)]
        config = {"phone": {"strategy": "keep"}}

        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            redacted, key, _ = replace(text, entities, config=config)

        assert "13912345678" not in redacted, "keep silently leaked phone"
        assert any("keep" in str(w.message).lower() for w in captured), (
            "no SecurityWarning emitted for keep downgrade"
        )

    def test_keep_on_ssn_downgrades(self):
        text = "ssn 123-45-6789"
        entities = [_entity("123-45-6789", "ssn", 4, 15)]
        config = {"ssn": {"strategy": "keep"}}

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            redacted, _, _ = replace(text, entities, config=config)

        assert "123-45-6789" not in redacted


class TestKeepWorksForSelfReferencePronouns:
    """The legitimate use case: pronouns / kinship that the LLM needs verbatim."""

    def test_keep_preserves_zh_pronoun(self):
        text = "我叫张伟, 电话13800138000"
        entities = [
            _entity("我", "self_reference", 0, 1),
            _entity("张伟", "person", 2, 4),
            _entity("13800138000", "phone", 8, 19),
        ]
        config = {"self_reference": {"strategy": "keep"}}

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # phone uses default, no keep applied
            redacted, key, _ = replace(text, entities, config=config)

        assert "我叫" in redacted, "self-reference pronoun should be preserved"
        assert "13800138000" not in redacted, "phone should be redacted"
        assert "张伟" not in redacted, "person should be redacted"
        assert "我" not in key.values(), "kept self_reference should not be in key dict"

    def test_keep_preserves_en_pronoun(self):
        text = "I am John"
        entities = [
            _entity("I", "self_reference", 0, 1),
            _entity("John", "person", 5, 9),
        ]
        config = {"self_reference": {"strategy": "keep"}}

        redacted, _, _ = replace(text, entities, config=config)
        assert redacted.startswith("I "), "pronoun 'I' should be preserved"
        assert "John" not in redacted

    def test_keep_rejects_self_reference_with_non_pronoun_text(self):
        """If L3 misclassifies a sensitive string as self_reference, downgrade."""
        text = "patient SSN 123-45-6789"
        # Layer-3 mistakenly assigns type=self_reference
        entities = [_entity("123-45-6789", "self_reference", 12, 23)]

        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            redacted, _, _ = replace(text, entities)

        assert "123-45-6789" not in redacted, (
            "self_reference with non-pronoun text leaked PII via keep"
        )
        assert any("keep" in str(w.message).lower() for w in captured)


class TestInvalidStrategyStillRejects:
    def test_unknown_strategy_still_raises(self):
        text = "phone 13912345678"
        entities = [_entity("13912345678", "phone", 6, 17)]
        config = {"phone": {"strategy": "bogus"}}

        with pytest.raises(ValueError) as exc:
            replace(text, entities, config=config)
        assert "Unknown strategy" in str(exc.value)
        assert "keep" in str(exc.value), "error message should list 'keep' as valid"
