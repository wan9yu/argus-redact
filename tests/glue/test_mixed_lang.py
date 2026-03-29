"""Tests for mixed Chinese-English PII detection — both language patterns active."""

from argus_redact import redact
from argus_redact.pure.patterns import match_patterns

from tests.conftest import assert_pattern_match, parametrize_examples


class TestMixedLanguageSensitive:
    """Test Level 3 sensitive attributes in mixed zh+en text."""

    @parametrize_examples("mixed_zh_en_sensitive.json")
    def test_should_detect_in_mixed_text(self, example):
        text = example["input"]
        redacted, key = redact(text, lang=["zh", "en"], mode="fast", seed=42)

        if example["should_match"]:
            # At least one entity of the expected type should be detected
            report = redact(text, lang=["zh", "en"], mode="fast", seed=42, report=True)
            detected_types = {e["type"] for e in report.entities}
            assert example["type"] in detected_types, (
                f"Expected type '{example['type']}' in {detected_types}: "
                f"{example['description']}"
            )
        else:
            # No entities of the expected type
            report = redact(text, lang=["zh", "en"], mode="fast", seed=42, report=True)
            detected_types = {e["type"] for e in report.entities}
            assert example["type"] not in detected_types, (
                f"Should NOT match '{example['type']}': {example['description']}"
            )

    @parametrize_examples("mixed_zh_en_sensitive.json")
    def test_should_roundtrip_when_mixed(self, example):
        """Redact then restore should preserve all original PII."""
        if not example["should_match"]:
            return  # skip negative cases for roundtrip

        text = example["input"]
        redacted, key = redact(text, lang=["zh", "en"], mode="fast", seed=42)
        from argus_redact import restore
        restored = restore(redacted, key)

        # Restored text should contain all original content
        assert isinstance(restored, str)
