"""Tests for English regex patterns — data-driven from JSON fixtures."""

import pytest
from argus_redact.lang.en.patterns import PATTERNS as EN_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.patterns import match_patterns

from tests.conftest import parametrize_examples

ALL_EN_PATTERNS = EN_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def en_patterns():
    return ALL_EN_PATTERNS


class TestEnglishPhone:
    @parametrize_examples("en_phone.json")
    def test_should_match_or_reject_when_phone_input(self, en_patterns, example):
        results = match_patterns(example["input"], en_patterns)
        phone_results = [r for r in results if r.type == "phone"]

        if example["should_match"]:
            assert len(phone_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in phone_results)
        else:
            assert len(phone_results) == 0, f"Should NOT match: {example['description']}"


class TestSSN:
    @parametrize_examples("en_ssn.json")
    def test_should_match_or_reject_when_ssn_input(self, en_patterns, example):
        results = match_patterns(example["input"], en_patterns)
        ssn_results = [r for r in results if r.type == "ssn"]

        if example["should_match"]:
            assert len(ssn_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in ssn_results)
        else:
            assert len(ssn_results) == 0, f"Should NOT match: {example['description']}"


class TestEnglishCreditCard:
    @parametrize_examples("en_credit_card.json")
    def test_should_match_or_reject_when_credit_card_input(self, en_patterns, example):
        results = match_patterns(example["input"], en_patterns)
        card_results = [r for r in results if r.type == "credit_card"]

        if example["should_match"]:
            assert len(card_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in card_results)
        else:
            assert len(card_results) == 0, f"Should NOT match: {example['description']}"
