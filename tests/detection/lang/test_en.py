"""Tests for English regex patterns — data-driven from JSON fixtures."""

import pytest

from argus_redact.lang.en.patterns import PATTERNS as EN_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.patterns import match_patterns
from tests.conftest import assert_pattern_match, parametrize_examples

ALL_EN_PATTERNS = EN_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def en_patterns():
    return ALL_EN_PATTERNS


class TestEnglishPhone:
    @parametrize_examples("en_phone.json")
    def test_should_match_or_reject_when_phone_input(self, en_patterns, example):
        results, _ = match_patterns(example["input"], en_patterns)
        assert_pattern_match(results, example, "phone")


class TestSSN:
    @parametrize_examples("en_ssn.json")
    def test_should_match_or_reject_when_ssn_input(self, en_patterns, example):
        results, _ = match_patterns(example["input"], en_patterns)
        assert_pattern_match(results, example, "ssn")


class TestEnglishCreditCard:
    @parametrize_examples("en_credit_card.json")
    def test_should_match_or_reject_when_credit_card_input(self, en_patterns, example):
        results, _ = match_patterns(example["input"], en_patterns)
        assert_pattern_match(results, example, "credit_card")


class TestEnglishDateOfBirth:
    @parametrize_examples("en_date_of_birth.json")
    def test_should_match_or_reject_when_dob_input(self, en_patterns, example):
        results, _ = match_patterns(example["input"], en_patterns)
        assert_pattern_match(results, example, "date_of_birth")


class TestEnglishSensitive:
    @parametrize_examples("en_sensitive.json")
    def test_should_match_or_reject_when_sensitive_input(self, en_patterns, example):
        results, _ = match_patterns(example["input"], en_patterns)
        assert_pattern_match(results, example)


class TestEnglishSelfReference:
    @parametrize_examples("en_self_reference.json")
    def test_should_match_or_reject_when_self_reference_input(self, en_patterns, example):
        results, _ = match_patterns(example["input"], en_patterns)
        typed = [r for r in results if r.type == "self_reference"]

        if example["should_match"]:
            if "expected_count" in example:
                assert len(typed) == example["expected_count"], (
                    f"Expected {example['expected_count']} matches: {example['description']}"
                )
            else:
                assert len(typed) >= 1, f"Expected match: {example['description']}"
                if "expected_text" in example:
                    assert any(r.text == example["expected_text"] for r in typed), (
                        f"Expected '{example['expected_text']}' but got "
                        f"{[r.text for r in typed]}: {example['description']}"
                    )
        else:
            assert len(typed) == 0, f"Should NOT match: {example['description']}"


class TestUSPassport:
    @parametrize_examples("en_passport.json")
    def test_should_match_or_reject_when_passport_input(self, en_patterns, example):
        results, _ = match_patterns(example["input"], en_patterns)
        assert_pattern_match(results, example, "us_passport")
