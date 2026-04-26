"""Tests for Brazilian regex patterns."""

import pytest

from argus_redact.lang.br.patterns import PATTERNS as BR_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
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
