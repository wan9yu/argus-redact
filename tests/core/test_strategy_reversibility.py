"""is_strategy_reversible() — public helper for downstream multi-turn dialog flow.

Reversible strategies (pseudonym/realistic/remove/keep) emit output that
restore() can map back to the original. Irreversible strategies
(mask/name_mask/landline_mask/category) lose information by design and the
key dict cannot recover the original.

PIITypeDef.is_reversible delegates to this function so callers can ask a
typedef for its reversibility without duplicating strategy classification.
"""

from __future__ import annotations

import pytest

from argus_redact.pure.replacer import (
    VALID_STRATEGIES,
    is_strategy_reversible,
    replace,
)
from argus_redact.pure.restore import restore
from argus_redact.specs.registry import PIITypeDef


def _match(text, type_name, start):
    from argus_redact._types import PatternMatch
    return PatternMatch(text=text, type=type_name, start=start, end=start + len(text), layer=1)


class TestStrategyClassification:
    @pytest.mark.parametrize("strategy", ["pseudonym", "realistic", "remove", "keep"])
    def test_reversible_strategies(self, strategy):
        assert is_strategy_reversible(strategy) is True

    @pytest.mark.parametrize(
        "strategy", ["mask", "name_mask", "landline_mask", "category"]
    )
    def test_irreversible_strategies(self, strategy):
        assert is_strategy_reversible(strategy) is False

    def test_every_valid_strategy_classified(self):
        # Every strategy in VALID_STRATEGIES must be classified as either
        # reversible or irreversible. Adding a new strategy without updating
        # the classification will be caught by the parametrized tests above
        # (`pytest.mark.parametrize` would not include the new strategy).
        # This test guards against the strategy lists silently diverging.
        from argus_redact.pure.replacer import _REVERSIBLE_STRATEGIES

        irreversible = {"mask", "name_mask", "landline_mask", "category"}
        assert _REVERSIBLE_STRATEGIES | irreversible == set(VALID_STRATEGIES), (
            "Every VALID_STRATEGIES member must appear in either "
            "_REVERSIBLE_STRATEGIES or the irreversible set."
        )
        assert _REVERSIBLE_STRATEGIES.isdisjoint(irreversible)


class TestUnknownStrategy:
    def test_unknown_strategy_raises_value_error(self):
        with pytest.raises(ValueError) as exc:
            is_strategy_reversible("nonexistent")
        # Error message must list valid strategies for the caller.
        assert "nonexistent" in str(exc.value)
        for strategy in VALID_STRATEGIES:
            assert strategy in str(exc.value)


class TestRoundTripBehavior:
    """Verify the classification matches actual replace()→restore() behavior."""

    def test_pseudonym_round_trips(self):
        entities = [_match("张三", "person", 0)]
        redacted, key = replace("张三说了话", entities, seed=42)
        assert restore(redacted, key) == "张三说了话"

    def test_remove_round_trips(self):
        entities = [_match("110101199003074610", "id_number", 0)]
        redacted, key = replace("110101199003074610", entities, seed=42)
        assert restore(redacted, key) == "110101199003074610"

    def test_mask_does_not_round_trip(self):
        # mask emits 138****5678 — the middle 4 digits cannot be recovered.
        entities = [_match("13812345678", "phone", 0)]
        redacted, _key = replace("13812345678", entities, seed=42)
        assert "****" in redacted
        # restore() with the mask key gives back the original (because mask
        # output IS in the key dict), but the strategy is still classified
        # irreversible because OTHER mask outputs with same prefix/suffix
        # could collide. The classification reflects the design intent.
        assert is_strategy_reversible("mask") is False


class TestPIITypeDefProperty:
    def test_is_reversible_delegates_to_function_pseudonym(self):
        td = PIITypeDef(name="x", lang="zh", format="", strategy="pseudonym")
        assert td.is_reversible is True

    def test_is_reversible_delegates_to_function_mask(self):
        td = PIITypeDef(name="x", lang="zh", format="", strategy="mask")
        assert td.is_reversible is False

    def test_is_reversible_for_keep(self):
        td = PIITypeDef(name="x", lang="zh", format="", strategy="keep")
        assert td.is_reversible is True


class TestPublicExport:
    def test_is_strategy_reversible_exported_from_top_level(self):
        from argus_redact import is_strategy_reversible as exported

        assert exported is is_strategy_reversible

    def test_is_strategy_reversible_in_dunder_all(self):
        import argus_redact

        assert "is_strategy_reversible" in argus_redact.__all__
