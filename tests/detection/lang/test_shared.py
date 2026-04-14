"""Tests for shared (cross-language) patterns — data-driven from JSON fixtures."""

from argus_redact.pure.patterns import match_patterns

from tests.conftest import assert_pattern_match, parametrize_examples


class TestIPAddress:
    @parametrize_examples("shared_ip.json")
    def test_should_match_or_reject_when_ip_input(self, shared_patterns, example):
        results, _ = match_patterns(example["input"], shared_patterns)
        assert_pattern_match(results, example, "ip_address")


class TestMACAddress:
    @parametrize_examples("shared_mac.json")
    def test_should_match_or_reject_when_mac_input(self, shared_patterns, example):
        results, _ = match_patterns(example["input"], shared_patterns)
        assert_pattern_match(results, example, "mac_address")


class TestIMEI:
    @parametrize_examples("shared_imei.json")
    def test_should_match_or_reject_when_imei_input(self, shared_patterns, example):
        results, _ = match_patterns(example["input"], shared_patterns)
        assert_pattern_match(results, example, "imei")


class TestURLToken:
    @parametrize_examples("shared_url_token.json")
    def test_should_match_or_reject_when_url_token_input(self, shared_patterns, example):
        results, _ = match_patterns(example["input"], shared_patterns)
        assert_pattern_match(results, example, "url_token")


class TestGender:
    @parametrize_examples("shared_gender.json")
    def test_should_match_or_reject_when_gender_input(self, shared_patterns, example):
        results, _ = match_patterns(example["input"], shared_patterns)
        assert_pattern_match(results, example, "gender")


class TestAge:
    @parametrize_examples("zh_age.json")
    def test_should_match_or_reject_when_age_input(self, shared_patterns, example):
        results, _ = match_patterns(example["input"], shared_patterns)
        assert_pattern_match(results, example, "age")


class TestEmailPattern:
    @parametrize_examples("email.json")
    def test_should_match_or_reject_when_email_input(self, shared_patterns, example):
        results, _ = match_patterns(example["input"], shared_patterns)
        assert_pattern_match(results, example, "email")


class TestIBAN:
    @parametrize_examples("iban.json")
    def test_should_match_or_reject_when_iban_input(self, shared_patterns, example):
        results, _ = match_patterns(example["input"], shared_patterns)
        assert_pattern_match(results, example, "iban")
