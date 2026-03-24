"""Tests for mixed language redact — zh+en combined."""

from argus_redact import redact, restore

from tests.conftest import parametrize_examples


class TestMixedLanguageRedact:
    @parametrize_examples("mixed_lang.json")
    def test_should_redact_all_pii_when_mixed_language(self, example):
        original = example["input"]

        redacted, key = redact(original, seed=42, mode="fast", lang=["zh", "en"])

        for pii in example["pii_values"]:
            assert (
                pii not in redacted
            ), f"PII '{pii}' still in redacted text: {example['description']}"

        restored = restore(redacted, key)
        for pii in example["pii_values"]:
            assert pii in restored, f"PII '{pii}' not recovered: {example['description']}"
