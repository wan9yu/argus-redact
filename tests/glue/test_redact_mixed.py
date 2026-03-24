"""Tests for mixed language redact — multi-language combined."""

from argus_redact import redact, restore

from tests.conftest import parametrize_examples


class TestMixedLanguageRedact:
    @parametrize_examples("mixed_lang.json")
    def test_should_redact_and_restore_when_mixed_language(self, example):
        original = example["input"]
        lang = example.get("lang", ["zh", "en"])

        redacted, key = redact(original, seed=42, mode="fast", lang=lang)

        if example["pii_values"]:
            for pii in example["pii_values"]:
                assert (
                    pii not in redacted
                ), f"PII '{pii}' still in redacted text: {example['description']}"
            restored = restore(redacted, key)
            for pii in example["pii_values"]:
                assert pii in restored, f"PII '{pii}' not recovered: {example['description']}"
        else:
            assert redacted == original
            assert key == {}
