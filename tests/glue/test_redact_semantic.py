"""Tests for redact() with Layer 3 semantic detection (mocked Ollama)."""

from unittest.mock import MagicMock, patch

from argus_redact import redact, restore
from argus_redact._types import NEREntity


def _mock_semantic_adapter(entity_map: dict[str, list[NEREntity]]):
    adapter = MagicMock()

    def detect(text):
        for key, entities in entity_map.items():
            if key in text:
                return entities
        return []

    adapter.detect.side_effect = detect
    return adapter


class TestRedactWithSemantic:
    def test_should_detect_implicit_pii_when_auto_mode(self):
        adapter = _mock_semantic_adapter(
            {
                "那个地方": [
                    NEREntity("那个地方", "location", 8, 12, 0.7),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_semantic_adapter", return_value=adapter):
            redacted, key = redact(
                "老王说他上周在那个地方见了人",
                seed=42,
                mode="auto",
                lang="zh",
            )

        assert "那个地方" not in redacted
        assert "那个地方" in key.values()

    def test_should_skip_semantic_when_ner_mode(self):
        adapter = _mock_semantic_adapter(
            {
                "那个地方": [
                    NEREntity("那个地方", "location", 8, 12, 0.7),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_semantic_adapter", return_value=adapter):
            redacted, key = redact(
                "老王说他上周在那个地方见了人",
                seed=42,
                mode="ner",
                lang="zh",
            )

        assert "那个地方" in redacted
        adapter.detect.assert_not_called()

    def test_should_skip_semantic_when_fast_mode(self):
        adapter = _mock_semantic_adapter(
            {
                "那个地方": [
                    NEREntity("那个地方", "location", 8, 12, 0.7),
                ],
            }
        )

        with patch("argus_redact.glue.redact._get_semantic_adapter", return_value=adapter):
            redacted, key = redact(
                "老王说他上周在那个地方见了人",
                seed=42,
                mode="fast",
                lang="zh",
            )

        assert "那个地方" in redacted
        adapter.detect.assert_not_called()

    def test_should_merge_all_three_layers_when_auto(self):
        ner_adapter = MagicMock()
        ner_adapter.detect.return_value = [
            NEREntity("老王", "person", 0, 2, 0.85),
        ]

        sem_adapter = _mock_semantic_adapter(
            {
                "那个地方": [
                    NEREntity("那个地方", "location", 8, 12, 0.7),
                ],
            }
        )

        with (
            patch("argus_redact.glue.redact._get_ner_adapters", return_value=[ner_adapter]),
            patch("argus_redact.glue.redact._get_semantic_adapter", return_value=sem_adapter),
        ):
            text = "老王说他上周在那个地方见了人，电话13812345678"
            redacted, key = redact(text, seed=42, mode="auto", lang="zh")

        assert "老王" not in redacted
        assert "那个地方" not in redacted
        assert "13812345678" not in redacted

        restored = restore(redacted, key)
        assert "老王" in restored
        assert "那个地方" in restored
        assert "13812345678" in restored

    def test_should_continue_when_semantic_fails(self):
        adapter = MagicMock()
        adapter.detect.side_effect = Exception("LLM timeout")

        with patch("argus_redact.glue.redact._get_semantic_adapter", return_value=adapter):
            redacted, key = redact(
                "电话13812345678",
                seed=42,
                mode="auto",
                lang="zh",
            )

        assert "13812345678" not in redacted
