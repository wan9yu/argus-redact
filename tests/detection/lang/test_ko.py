"""Tests for Korean regex patterns — data-driven from JSON fixtures."""

import pytest
from argus_redact.lang.ko.patterns import PATTERNS as KO_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.patterns import match_patterns

from tests.conftest import parametrize_examples

ALL_KO_PATTERNS = KO_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def ko_patterns():
    return ALL_KO_PATTERNS


class TestKoreanPhone:
    @parametrize_examples("ko_phone.json")
    def test_should_match_or_reject_when_phone_input(self, ko_patterns, example):
        results, _ = match_patterns(example["input"], ko_patterns)
        phone_results = [r for r in results if r.type == "phone"]

        if example["should_match"]:
            assert len(phone_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in phone_results)
        else:
            assert len(phone_results) == 0, f"Should NOT match: {example['description']}"


class TestRRN:
    @parametrize_examples("ko_rrn.json")
    def test_should_match_or_reject_when_rrn_input(self, ko_patterns, example):
        results, _ = match_patterns(example["input"], ko_patterns)
        rrn_results = [r for r in results if r.type == "rrn"]

        if example["should_match"]:
            assert len(rrn_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in rrn_results)
        else:
            assert len(rrn_results) == 0, f"Should NOT match: {example['description']}"
