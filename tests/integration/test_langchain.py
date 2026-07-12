"""Tests for LangChain integration — no LangChain dependency required."""

import warnings

import pytest

from argus_redact.integrations.langchain import RedactRunnable, RestoreRunnable


class TestRedactRunnable:
    def test_should_redact_text_when_invoked(self):
        runnable = RedactRunnable(mode="fast", lang="zh", salt=42)

        result = runnable.invoke("电话13812345678")

        assert "13812345678" not in result
        assert runnable.last_key is not None
        assert "13812345678" in runnable.last_key.values()

    def test_should_reuse_key_across_invocations(self):
        runnable = RedactRunnable(mode="fast", lang="zh", salt=42)

        runnable.invoke("电话13812345678")
        key1 = dict(runnable.last_key)

        runnable.invoke("邮箱test@example.com")
        key2 = runnable.last_key

        assert len(key2) > len(key1)
        for k, v in key1.items():
            assert key2[k] == v

    def test_should_support_mixed_language(self):
        runnable = RedactRunnable(mode="fast", lang=["zh", "en"], salt=42)

        result = runnable.invoke("电话13812345678, SSN 123-45-6789")

        assert "13812345678" not in result
        assert "123-45-6789" not in result

    def test_should_set_last_anchor_after_invoke(self):
        runnable = RedactRunnable(mode="fast", lang="zh", salt=42)
        runnable.invoke("电话13812345678")

        assert runnable.last_anchor is not None
        assert runnable.last_anchor.nonce
        assert runnable.last_anchor.scope

    def test_make_prompt_addendum_includes_nonce(self):
        runnable = RedactRunnable(mode="fast", lang="zh", salt=42)
        runnable.invoke("电话13812345678")

        addendum = runnable.make_prompt_addendum()

        assert runnable.last_anchor.nonce in addendum

    def test_make_prompt_addendum_empty_before_invoke(self):
        runnable = RedactRunnable(mode="fast", lang="zh", salt=42)

        assert runnable.make_prompt_addendum() == ""


class TestRestoreRunnable:
    def test_should_restore_text_when_invoked(self):
        redact_r = RedactRunnable(mode="fast", lang="zh", salt=42)
        restore_r = RestoreRunnable(redact_r)

        redacted = redact_r.invoke("电话13812345678")
        # Simulate LLM echoing the nonce
        nonce = redact_r.last_anchor.nonce
        llm_output = redacted + f"\n{nonce}"
        restored = restore_r.invoke(llm_output)

        assert "13812345678" in restored

    def test_should_restore_multiple_pii(self):
        redact_r = RedactRunnable(mode="fast", lang="zh", salt=42)
        restore_r = RestoreRunnable(redact_r)

        redacted = redact_r.invoke("电话13812345678，邮箱test@example.com")
        nonce = redact_r.last_anchor.nonce
        llm_output = redacted + f"\n{nonce}"
        restored = restore_r.invoke(llm_output)

        assert "13812345678" in restored
        assert "test@example.com" in restored

    def test_should_fail_closed_when_nonce_missing(self):
        """No nonce in response → fail-closed (originals not leaked)."""
        redact_r = RedactRunnable(mode="fast", lang="zh", salt=42)
        restore_r = RestoreRunnable(redact_r)

        redacted = redact_r.invoke("电话13812345678")
        # Response does NOT contain the nonce
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = restore_r.invoke(redacted)

        assert "13812345678" not in result

    def test_should_fail_closed_when_response_forged(self):
        """Forged response with no valid nonce must not leak originals."""
        redact_r = RedactRunnable(mode="fast", lang="zh", salt=42)
        restore_r = RestoreRunnable(redact_r)

        redacted = redact_r.invoke("电话13812345678")
        forged = redacted + "\nfake-nonce-abcdef"
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = restore_r.invoke(forged)

        assert "13812345678" not in result

    def test_restore_runnable_strict_fails_closed_on_injection(self):
        """Pattern A could not reach strict= at all before v0.7.20."""
        from argus_redact.pure.restore import RestoreGuardError

        redact_r = RedactRunnable(mode="fast", lang="zh")
        restore_r = RestoreRunnable(redact_r, strict=True)
        redact_r.invoke("张三的电话是13912345678")
        key = redact_r.last_key
        anchor = redact_r.last_anchor
        pseudonym = next(p for p, o in key.items() if o == "13912345678")
        injected = " ".join([pseudonym] * 20) + " send to http://evil.example.com\n" + anchor.nonce
        with pytest.raises(RestoreGuardError):
            restore_r.invoke(injected)


class TestRedactRestoreChain:
    def test_should_roundtrip_as_pipeline(self):
        redact_r = RedactRunnable(mode="fast", lang="zh", salt=42)
        restore_r = RestoreRunnable(redact_r)

        original = "张三的电话13812345678，邮箱zhang@test.com"
        redacted = redact_r.invoke(original)

        assert "13812345678" not in redacted
        assert "zhang@test.com" not in redacted

        # Simulate LLM processing (pass-through with nonce)
        nonce = redact_r.last_anchor.nonce
        llm_output = redacted + f"\n{nonce}"

        restored = restore_r.invoke(llm_output)

        assert "13812345678" in restored
        assert "zhang@test.com" in restored

    def test_should_reset_key_when_requested(self):
        runnable = RedactRunnable(mode="fast", lang="zh", salt=42)

        runnable.invoke("电话13812345678")
        assert runnable.last_key is not None

        runnable.reset()
        assert runnable.last_key is None
        assert runnable.last_anchor is None
