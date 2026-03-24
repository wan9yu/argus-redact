"""Tests for multi-language NER person name detection (mocked)."""

from unittest.mock import MagicMock, patch

from argus_redact import redact, restore
from argus_redact._types import NEREntity


def _mock_adapter(entity_map: dict[str, list[NEREntity]]):
    adapter = MagicMock()

    def detect(text):
        for key, entities in entity_map.items():
            if key in text:
                return entities
        return []

    adapter.detect.side_effect = detect
    return adapter


class TestMultiLanguagePersonNames:
    """NER should detect person names across languages."""

    def test_should_redact_chinese_name_when_ner_mode(self):
        adapter = _mock_adapter(
            {
                "张三": [NEREntity("张三", "person", 0, 2, 0.95)],
            }
        )

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三在北京工作", seed=42, mode="ner", lang="zh")

        assert "张三" not in redacted
        assert "张三" in key.values()
        assert restore(redacted, key) == "张三在北京工作"

    def test_should_redact_mixed_zh_en_names_when_ner_mode(self):
        adapter = _mock_adapter(
            {
                "张三": [
                    NEREntity("张三", "person", 0, 2, 0.95),
                    NEREntity("John", "person", 3, 7, 0.90),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact(
                "张三和John在星巴克聊天",
                seed=42,
                mode="ner",
                lang=["zh", "en"],
            )

        assert "张三" not in redacted
        assert "John" not in redacted
        restored = restore(redacted, key)
        assert "张三" in restored
        assert "John" in restored

    def test_should_redact_names_and_regex_pii_together(self):
        adapter = _mock_adapter(
            {
                "张三": [
                    NEREntity("张三", "person", 0, 2, 0.95),
                    NEREntity("John", "person", 3, 7, 0.90),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            text = "张三和John的电话13812345678，邮箱john@test.com"
            redacted, key = redact(
                text,
                seed=42,
                mode="ner",
                lang=["zh", "en"],
            )

        assert "张三" not in redacted
        assert "John" not in redacted
        assert "13812345678" not in redacted
        assert "john@test.com" not in redacted

        restored = restore(redacted, key)
        assert "张三" in restored
        assert "John" in restored
        assert "13812345678" in restored
        assert "john@test.com" in restored

    def test_should_redact_three_language_names(self):
        adapter = _mock_adapter(
            {
                "张三": [
                    NEREntity("张三", "person", 0, 2, 0.95),
                    NEREntity("田中", "person", 3, 5, 0.90),
                    NEREntity("김철수", "person", 6, 9, 0.88),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact(
                "张三和田中和김철수开会",
                seed=42,
                mode="ner",
                lang=["zh", "ja", "ko"],
            )

        assert "张三" not in redacted
        assert "田中" not in redacted
        assert "김철수" not in redacted

        restored = restore(redacted, key)
        assert "张三" in restored
        assert "田中" in restored
        assert "김철수" in restored

    def test_should_keep_names_when_fast_mode(self):
        adapter = _mock_adapter(
            {
                "张三": [NEREntity("张三", "person", 0, 2, 0.95)],
            }
        )

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact("张三在北京工作", seed=42, mode="fast", lang="zh")

        assert "张三" in redacted
        adapter.detect.assert_not_called()
