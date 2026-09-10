"""Tests for Indian regex patterns."""

import pytest

from argus_redact._types import PatternMatch
from argus_redact.lang.in_.patterns import PATTERNS as IN_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.hints import _is_interaction_command, _is_kinship
from argus_redact.pure.patterns import match_patterns
from tests.conftest import parametrize_examples

ALL_IN_PATTERNS = IN_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def in_patterns():
    return ALL_IN_PATTERNS


class TestIndianPatterns:
    @parametrize_examples("in_patterns.json")
    def test_should_match_or_reject_when_input(self, in_patterns, example):
        results, _ = match_patterns(example["input"], in_patterns)
        typed = [r for r in results if r.type == example["type"]]

        if example["should_match"]:
            assert len(typed) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in typed)
        else:
            assert len(typed) == 0, f"Should NOT match: {example['description']}"


class TestIndianHints:
    """Indian English kinship + command-mode hints."""

    def test_is_kinship_should_recognize_my_papa(self):
        entity = PatternMatch(
            text="my papa", type="self_reference", start=0, end=7, confidence=1.0, layer=1
        )
        assert _is_kinship(entity)

    def test_is_interaction_command_should_return_true_when_text_is_a_polite_command(self):
        assert _is_interaction_command("Kindly share your phone number.")
        assert _is_interaction_command("Please do the needful.")

    def test_is_interaction_command_should_return_false_when_text_is_narrative(self):
        assert not _is_interaction_command("The Mumbai office opens at 9 AM.")
