"""Compare small vs large Ollama models for Layer 3 quality.

Run with: pytest tests/impure/test_ollama_models.py -m semantic -v -s
"""

import pytest
import requests

pytestmark = pytest.mark.semantic


def _ollama_has_model(model):
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=2)
        models = [m["name"] for m in r.json().get("models", [])]
        return model in models
    except Exception:
        return False


@pytest.fixture(scope="module")
def adapter_3b():
    if not _ollama_has_model("qwen2.5:3b"):
        pytest.skip("qwen2.5:3b not available")
    from argus_redact.impure.ollama_adapter import OllamaAdapter

    return OllamaAdapter(model="qwen2.5:3b")


class TestSmallModelQuality:
    """qwen2.5:3b should detect basic implicit PII."""

    def test_should_detect_nickname(self, adapter_3b):
        results = adapter_3b.detect("老王说他上周去了医院")

        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1

    def test_should_detect_implicit_reference(self, adapter_3b):
        results = adapter_3b.detect("住在那个小区的那个医生说了那件事")

        assert len(results) >= 1

    def test_should_return_valid_offsets(self, adapter_3b):
        text = "老王和小李在那个地方聊了聊"
        results = adapter_3b.detect(text)

        for r in results:
            assert 0 <= r.start < r.end <= len(text)
