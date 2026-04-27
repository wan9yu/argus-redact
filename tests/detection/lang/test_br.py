"""Tests for Brazilian regex patterns."""

import pytest

from argus_redact._types import PatternMatch
from argus_redact.lang.br.patterns import PATTERNS as BR_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.hints import _is_interaction_command, _is_kinship
from argus_redact.pure.patterns import match_patterns
from tests.conftest import assert_pattern_match, parametrize_examples

ALL_BR_PATTERNS = BR_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def br_patterns():
    return ALL_BR_PATTERNS


class TestBrazilianPatterns:
    @parametrize_examples("br_patterns.json")
    def test_should_match_or_reject_when_input(self, br_patterns, example):
        results, _ = match_patterns(example["input"], br_patterns)
        assert_pattern_match(results, example)


class TestBrazilianHints:
    """Brazilian Portuguese kinship + command-mode hints."""

    def test_kinship_minha_mae_is_kinship(self):
        entity = PatternMatch(
            text="minha mãe", type="self_reference", start=0, end=9, confidence=1.0, layer=1
        )
        assert _is_kinship(entity)

    def test_command_pattern_marks_command_mode(self):
        assert _is_interaction_command("Por favor, me diga o número.")
        assert _is_interaction_command("Você pode me ajudar?")

    def test_narrative_br_is_not_command(self):
        assert not _is_interaction_command("São Paulo é a maior cidade do Brasil.")
