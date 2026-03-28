"""Tests for Brazilian regex patterns."""

import pytest
from argus_redact.lang.br.patterns import PATTERNS as BR_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.patterns import match_patterns

from tests.conftest import parametrize_examples

ALL_BR_PATTERNS = BR_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def br_patterns():
    return ALL_BR_PATTERNS


class TestBrazilianPatterns:
    @parametrize_examples("br_patterns.json")
    def test_should_match_or_reject_when_input(self, br_patterns, example):
        results = match_patterns(example["input"], br_patterns)
        typed = [r for r in results if r.type == example["type"]]

        if example["should_match"]:
            assert len(typed) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in typed)
        else:
            assert len(typed) == 0, f"Should NOT match: {example['description']}"
