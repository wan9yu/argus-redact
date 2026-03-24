"""Tests for shared (cross-language) patterns — data-driven from JSON fixtures."""

from argus_redact.pure.patterns import match_patterns

from tests.conftest import parametrize_examples


class TestEmailPattern:
    @parametrize_examples("email.json")
    def test_should_match_or_reject_when_email_input(self, shared_patterns, example):
        results = match_patterns(example["input"], shared_patterns)
        email_results = [r for r in results if r.type == "email"]

        if example["should_match"]:
            assert len(email_results) >= 1, f"Expected match: {example['description']}"
            if "expected_text" in example:
                assert any(r.text == example["expected_text"] for r in email_results)
        else:
            assert len(email_results) == 0, f"Should NOT match: {example['description']}"
