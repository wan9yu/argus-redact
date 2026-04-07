"""Tests for Japanese regex patterns — data-driven from JSON fixtures."""

import pytest
from argus_redact.lang.ja.patterns import PATTERNS as JA_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.patterns import match_patterns

from tests.conftest import parametrize_examples

ALL_JA_PATTERNS = JA_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def ja_patterns():
    return ALL_JA_PATTERNS


class TestJapanesePhone:
    @parametrize_examples("ja_phone.json")
    def test_should_match_or_reject_when_phone_input(self, ja_patterns, example):
        results, _ = match_patterns(example["input"], ja_patterns)
        phone_results = [r for r in results if r.type == "phone"]

        if example["should_match"]:
            assert len(phone_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in phone_results)
        else:
            assert len(phone_results) == 0, f"Should NOT match: {example['description']}"


class TestMyNumber:
    @parametrize_examples("ja_my_number.json")
    def test_should_match_or_reject_when_my_number_input(self, ja_patterns, example):
        results, _ = match_patterns(example["input"], ja_patterns)
        mn_results = [r for r in results if r.type == "my_number"]

        if example["should_match"]:
            assert len(mn_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in mn_results)
        else:
            assert len(mn_results) == 0, f"Should NOT match: {example['description']}"
