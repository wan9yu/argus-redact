"""Tests for German regex patterns."""

import pytest

from argus_redact._types import PatternMatch
from argus_redact.lang.de.patterns import PATTERNS as DE_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.hints import _is_interaction_command, _is_kinship
from argus_redact.pure.patterns import match_patterns
from tests.conftest import parametrize_examples

ALL_DE_PATTERNS = DE_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def de_patterns():
    return ALL_DE_PATTERNS


class TestGermanPatterns:
    @parametrize_examples("de_patterns.json")
    def test_should_match_or_reject_when_input(self, de_patterns, example):
        results, _ = match_patterns(example["input"], de_patterns)
        typed = [r for r in results if r.type == example["type"]]

        if example["should_match"]:
            assert len(typed) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in typed)
        else:
            assert len(typed) == 0, f"Should NOT match: {example['description']}"


class TestGermanHints:
    """German kinship + command-mode hints."""

    def test_kinship_prefix_is_kinship(self):
        entity = PatternMatch(
            text="meine Mutter", type="self_reference", start=0, end=12, confidence=1.0, layer=1
        )
        assert _is_kinship(entity)

    def test_command_pattern_marks_command_mode(self):
        assert _is_interaction_command("Können Sie mir die Telefonnummer sagen?")
        assert _is_interaction_command("Bitte kontaktieren Sie mich.")

    def test_narrative_german_is_not_command(self):
        assert not _is_interaction_command("Herr Schmidt arbeitet in München.")
