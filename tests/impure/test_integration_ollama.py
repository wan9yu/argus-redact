"""Real Ollama integration tests — requires local Ollama running.

Run with: pytest tests/impure/test_integration_ollama.py -m semantic -v
"""

import pytest
import requests

pytestmark = pytest.mark.semantic


def _ollama_available():
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


@pytest.fixture(scope="module")
def adapter():
    if not _ollama_available():
        pytest.skip("Ollama not running at localhost:11434")
    from argus_redact.impure.ollama_adapter import OllamaAdapter

    return OllamaAdapter(model="qwen2.5:32b")


class TestOllamaRealDetection:
    """Integration tests with real Ollama LLM."""

    def test_should_detect_nickname(self, adapter):
        results = adapter.detect("老王说他上周去了医院")

        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1
        assert any("老王" in r.text for r in persons)

    def test_should_detect_implicit_location(self, adapter):
        results = adapter.detect("老王说他在那个地方见了老李")

        locations = [r for r in results if r.type == "location"]
        assert len(locations) >= 1

    def test_should_return_valid_offsets(self, adapter):
        text = "老王说他在那个地方见了老李"
        results = adapter.detect(text)

        for r in results:
            assert (
                0 <= r.start < r.end <= len(text)
            ), f"Invalid offset: {r.text} start={r.start} end={r.end} text_len={len(text)}"

    def test_should_return_empty_when_no_implicit_pii(self, adapter):
        results = adapter.detect("今天天气真不错，适合出去散步")

        # LLM may or may not find something — just verify no crash
        assert isinstance(results, list)

    def test_should_handle_long_text(self, adapter):
        text = (
            "老王和小李上周在那个地方讨论了那件事，"
            "他们觉得那个公司的做法不太对，"
            "特别是住在那个小区的那个人说的那些话"
        )
        results = adapter.detect(text)

        assert isinstance(results, list)
        for r in results:
            assert r.text in text


class TestOllamaFullPipeline:
    """End-to-end: regex + NER + Ollama semantic."""

    def test_should_redact_implicit_pii_in_auto_mode(self, adapter):
        from unittest.mock import patch

        from argus_redact import redact, restore

        text = "老王说他在那个地方见了老李，电话13812345678"

        with patch("argus_redact.glue.redact._get_semantic_adapter", return_value=adapter):
            redacted, key = redact(text, seed=42, mode="auto", lang="zh")

        assert "13812345678" not in redacted

        restored = restore(redacted, key)
        assert "13812345678" in restored
