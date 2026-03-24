"""Tests for LangChain integration — no LangChain dependency required."""

from argus_redact.integrations.langchain import RedactRunnable, RestoreRunnable


class TestRedactRunnable:
    def test_should_redact_text_when_invoked(self):
        runnable = RedactRunnable(mode="fast", lang="zh", seed=42)

        result = runnable.invoke("电话13812345678")

        assert "13812345678" not in result
        assert runnable.last_key is not None
        assert "13812345678" in runnable.last_key.values()

    def test_should_reuse_key_across_invocations(self):
        runnable = RedactRunnable(mode="fast", lang="zh", seed=42)

        runnable.invoke("电话13812345678")
        key1 = dict(runnable.last_key)

        runnable.invoke("邮箱test@example.com")
        key2 = runnable.last_key

        assert len(key2) > len(key1)
        for k, v in key1.items():
            assert key2[k] == v

    def test_should_support_mixed_language(self):
        runnable = RedactRunnable(mode="fast", lang=["zh", "en"], seed=42)

        result = runnable.invoke("电话13812345678, SSN 123-45-6789")

        assert "13812345678" not in result
        assert "123-45-6789" not in result


class TestRestoreRunnable:
    def test_should_restore_text_when_invoked(self):
        redact_r = RedactRunnable(mode="fast", lang="zh", seed=42)
        restore_r = RestoreRunnable(redact_r)

        redacted = redact_r.invoke("电话13812345678")
        restored = restore_r.invoke(redacted)

        assert "13812345678" in restored

    def test_should_restore_multiple_pii(self):
        redact_r = RedactRunnable(mode="fast", lang="zh", seed=42)
        restore_r = RestoreRunnable(redact_r)

        redacted = redact_r.invoke("电话13812345678，邮箱test@example.com")
        restored = restore_r.invoke(redacted)

        assert "13812345678" in restored
        assert "test@example.com" in restored


class TestRedactRestoreChain:
    def test_should_roundtrip_as_pipeline(self):
        redact_r = RedactRunnable(mode="fast", lang="zh", seed=42)
        restore_r = RestoreRunnable(redact_r)

        original = "张三的电话13812345678，邮箱zhang@test.com"
        redacted = redact_r.invoke(original)

        assert "13812345678" not in redacted
        assert "zhang@test.com" not in redacted

        # Simulate LLM processing (pass-through)
        llm_output = redacted

        restored = restore_r.invoke(llm_output)

        assert "13812345678" in restored
        assert "zhang@test.com" in restored

    def test_should_reset_key_when_requested(self):
        runnable = RedactRunnable(mode="fast", lang="zh", seed=42)

        runnable.invoke("电话13812345678")
        assert runnable.last_key is not None

        runnable.reset()
        assert runnable.last_key is None
