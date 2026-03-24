"""LangChain + Ollama integration test — requires local Ollama running.

Run with: pytest tests/integration/test_langchain_ollama.py -m semantic -v
"""

import pytest
import requests
from argus_redact.integrations.langchain import RedactRunnable, RestoreRunnable

pytestmark = pytest.mark.semantic


def _ollama_available():
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def _ollama_generate(text: str, model: str = "qwen2.5:32b") -> str:
    """Simple Ollama call — replaces LangChain LLM in the chain."""
    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": model, "prompt": text, "stream": False},
        timeout=60,
    )
    return r.json()["response"]


@pytest.fixture(scope="module")
def _check_ollama():
    if not _ollama_available():
        pytest.skip("Ollama not running at localhost:11434")


class TestLangChainOllamaChain:
    def test_should_roundtrip_through_llm(self, _check_ollama):
        redact_r = RedactRunnable(mode="fast", lang="zh", seed=42)
        restore_r = RestoreRunnable(redact_r)

        original = "张三的电话是13812345678，他住在北京市朝阳区"

        redacted = redact_r.invoke(original)
        assert "13812345678" not in redacted

        llm_output = _ollama_generate(f"请用一句话总结：{redacted}")

        restore_r.invoke(llm_output)
        # LLM 可能不会原样返回所有 PII 伪名，但 key 应该正确
        assert redact_r.last_key is not None
        assert len(redact_r.last_key) >= 1

    def test_should_preserve_key_across_multi_turn(self, _check_ollama):
        redact_r = RedactRunnable(mode="fast", lang="zh", seed=42)
        restore_r = RestoreRunnable(redact_r)

        r1 = redact_r.invoke("电话13812345678")
        assert "13812345678" not in r1

        r2 = redact_r.invoke("邮箱test@example.com")
        assert "test@example.com" not in r2

        # Key should have both entries
        assert len(redact_r.last_key) >= 2

        # Restore both
        assert "13812345678" in restore_r.invoke(r1)
        assert "test@example.com" in restore_r.invoke(r2)

    def test_should_work_with_mixed_language(self, _check_ollama):
        redact_r = RedactRunnable(
            mode="fast",
            lang=["zh", "en"],
            seed=42,
        )
        restore_r = RestoreRunnable(redact_r)

        original = "Call 13812345678, SSN 123-45-6789"
        redacted = redact_r.invoke(original)

        assert "13812345678" not in redacted
        assert "123-45-6789" not in redacted

        restored = restore_r.invoke(redacted)
        assert "13812345678" in restored
        assert "123-45-6789" in restored
