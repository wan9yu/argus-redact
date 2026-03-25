"""Tests for LlamaIndex integration."""

from argus_redact.integrations.llamaindex import RedactTransform, RestoreTransform


class TestRedactTransform:
    def test_should_redact_when_called(self):
        t = RedactTransform(mode="fast", lang="zh", seed=42)

        result = t("电话13812345678")

        assert "13812345678" not in result
        assert t.last_key is not None

    def test_should_reuse_key_across_calls(self):
        t = RedactTransform(mode="fast", lang="zh", seed=42)

        t("电话13812345678")
        t("邮箱test@example.com")

        assert len(t.last_key) >= 2

    def test_should_support_mixed_language(self):
        t = RedactTransform(mode="fast", lang=["zh", "en"], seed=42)

        result = t("电话13812345678, SSN 123-45-6789")

        assert "13812345678" not in result
        assert "123-45-6789" not in result


class TestRestoreTransform:
    def test_should_restore_when_called(self):
        redact_t = RedactTransform(mode="fast", lang="zh", seed=42)
        restore_t = RestoreTransform(redact_t)

        redacted = redact_t("电话13812345678")
        restored = restore_t(redacted)

        assert "13812345678" in restored

    def test_should_roundtrip_multiple_pii(self):
        redact_t = RedactTransform(mode="fast", lang="zh", seed=42)
        restore_t = RestoreTransform(redact_t)

        redacted = redact_t("电话13812345678，邮箱test@example.com")
        restored = restore_t(redacted)

        assert "13812345678" in restored
        assert "test@example.com" in restored

    def test_should_return_unchanged_when_no_key(self):
        redact_t = RedactTransform(mode="fast", lang="zh", seed=42)
        restore_t = RestoreTransform(redact_t)

        result = restore_t("no redaction happened")

        assert result == "no redaction happened"


class TestResetAndPipeline:
    def test_should_reset_key(self):
        t = RedactTransform(mode="fast", lang="zh", seed=42)
        t("电话13812345678")
        assert t.last_key is not None

        t.reset()
        assert t.last_key is None

    def test_should_simulate_pipeline(self):
        redact_t = RedactTransform(mode="fast", lang="zh", seed=42)
        restore_t = RestoreTransform(redact_t)

        original = "张三电话13812345678"
        redacted = redact_t(original)
        llm_output = f"Summary: {redacted}"
        restored = restore_t(llm_output)

        assert "13812345678" in restored
