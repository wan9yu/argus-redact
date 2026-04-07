"""Tests for UK regex patterns."""

import pytest
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.lang.uk.patterns import PATTERNS as UK_PATTERNS
from argus_redact.pure.patterns import match_patterns

from tests.conftest import parametrize_examples

ALL_UK_PATTERNS = UK_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def uk_patterns():
    return ALL_UK_PATTERNS


class TestUKPatterns:
    @parametrize_examples("uk_patterns.json")
    def test_should_match_or_reject_when_input(self, uk_patterns, example):
        results, _ = match_patterns(example["input"], uk_patterns)
        typed = [r for r in results if r.type == example["type"]]

        if example["should_match"]:
            assert len(typed) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in typed)
        else:
            assert len(typed) == 0, f"Should NOT match: {example['description']}"
