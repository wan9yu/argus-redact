"""Tests for redact() with NER integration (mocked)."""

from unittest.mock import MagicMock, patch

from argus_redact import redact, restore
from argus_redact._types import NEREntity
from argus_redact.impure.ner import NERAdapter


def _mock_ner_adapter(entity_map: dict[str, list[NEREntity]]):
    """Create a mock NER adapter that returns entities based on text content."""
    adapter = MagicMock(spec=NERAdapter)

    def detect(text):
        for key, entities in entity_map.items():
            if key in text:
                return entities
        return []

    adapter.detect.side_effect = detect
    return adapter


class TestRedactWithNER:
    """redact() should use NER when mode is 'auto' or 'ner'."""

    def test_should_detect_person_name_when_ner_mode(self):
        adapter = _mock_ner_adapter(
            {
                "张三": [
                    NEREntity(text="张三", type="person", start=0, end=2, confidence=0.95),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三去了北京", seed=42, mode="ner", lang="zh")

        assert "张三" not in redacted
        assert "张三" in key.values()

    def test_should_detect_person_name_when_auto_mode(self):
        adapter = _mock_ner_adapter(
            {
                "张三": [
                    NEREntity(text="张三", type="person", start=0, end=2, confidence=0.95),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三去了北京", seed=42, mode="auto", lang="zh")

        assert "张三" not in redacted

    def test_should_skip_ner_when_fast_mode(self):
        adapter = _mock_ner_adapter(
            {
                "张三": [
                    NEREntity(text="张三", type="person", start=0, end=2, confidence=0.95),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三去了北京", seed=42, mode="fast", lang="zh")

        # fast mode = regex only, 张三 should NOT be redacted
        assert "张三" in redacted
        adapter.detect.assert_not_called()

    def test_should_merge_ner_and_regex_when_both_detect(self):
        adapter = _mock_ner_adapter(
            {
                "张三": [
                    NEREntity(text="张三", type="person", start=0, end=2, confidence=0.95),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact(
                "张三的手机号是13812345678",
                seed=42,
                mode="ner",
                lang="zh",
            )

        assert "张三" not in redacted
        assert "13812345678" not in redacted
        assert len(key) == 2

    def test_should_roundtrip_when_ner_entities_present(self):
        adapter = _mock_ner_adapter(
            {
                "张三": [
                    NEREntity(text="张三", type="person", start=0, end=2, confidence=0.95),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三说了话", seed=42, mode="ner", lang="zh")

        restored = restore(redacted, key)
        assert "张三" in restored
