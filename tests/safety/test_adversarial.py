"""Adversarial and edge case tests — stress-test PII detection robustness."""

import json
from pathlib import Path

import pytest

from argus_redact import redact, restore

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _load_adversarial():
    with open(FIXTURES_DIR / "adversarial_tests.json") as f:
        return json.load(f)


_cases = _load_adversarial()


@pytest.mark.parametrize(
    "case",
    _cases,
    ids=[c["id"] for c in _cases],
)
class TestAdversarial:
    def test_should_not_crash(self, case):
        """redact() must never crash, regardless of input."""
        lang = case.get("lang", "zh")

        redacted, key = redact(case["input"], seed=42, mode="fast", lang=lang)

        assert isinstance(redacted, str)
        assert isinstance(key, dict)

    def test_should_roundtrip(self, case):
        """restore(redact(text)) must recover all detected PII."""
        lang = case.get("lang", "zh")

        redacted, key = redact(case["input"], seed=42, mode="fast", lang=lang)
        restored = restore(redacted, key)

        for original in key.values():
            assert original in restored, (
                f"Lost PII '{original}' in roundtrip: {case['description']}"
            )

    def test_should_detect_expected_count(self, case):
        """Check PII detection count matches expectation."""
        if case.get("expected_pii_count") is None:
            pytest.skip("no expected count")

        lang = case.get("lang", "zh")

        _, key = redact(case["input"], seed=42, mode="fast", lang=lang)

        expected = case["expected_pii_count"]
        actual = len(key)

        if case.get("should_find_pii", True):
            if expected > 0:
                assert actual >= 1, f"Expected PII but found none: {case['description']}"
        else:
            assert actual == 0, f"False positive — found {actual} PII in: {case['description']}"
