"""Tests for Indian regex patterns."""

import pytest
from argus_redact.lang.in_.patterns import PATTERNS as IN_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.patterns import match_patterns

from tests.conftest import parametrize_examples

ALL_IN_PATTERNS = IN_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def in_patterns():
    return ALL_IN_PATTERNS


class TestIndianPatterns:
    @parametrize_examples("in_patterns.json")
    def test_should_match_or_reject_when_input(self, in_patterns, example):
        results = match_patterns(example["input"], in_patterns)
        typed = [r for r in results if r.type == example["type"]]

        if example["should_match"]:
            assert len(typed) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in typed)
        else:
            assert len(typed) == 0, f"Should NOT match: {example['description']}"
