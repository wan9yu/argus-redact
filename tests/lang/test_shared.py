"""Tests for shared (cross-language) patterns — data-driven from JSON fixtures."""

from argus_redact.pure.patterns import match_patterns

from tests.conftest import assert_pattern_match, parametrize_examples


class TestIPAddress:
    @parametrize_examples("shared_ip.json")
    def test_should_match_or_reject_when_ip_input(self, shared_patterns, example):
        results = match_patterns(example["input"], shared_patterns)
        assert_pattern_match(results, example, "ip_address")


class TestEmailPattern:
    @parametrize_examples("email.json")
    def test_should_match_or_reject_when_email_input(self, shared_patterns, example):
        results = match_patterns(example["input"], shared_patterns)
        assert_pattern_match(results, example, "email")
