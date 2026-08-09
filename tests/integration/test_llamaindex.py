"""Tests for LlamaIndex integration."""

import warnings

import pytest

from argus_redact.exceptions import SessionStateError
from argus_redact.integrations.llamaindex import RedactTransform, RestoreTransform


class TestRedactTransform:
    def test_should_redact_when_called(self):
        t = RedactTransform(mode="fast", lang="zh", salt=42)

        result = t("电话13812345678")

        assert "13812345678" not in result
        assert t.last_key is not None

    def test_should_reuse_key_across_calls(self):
        t = RedactTransform(mode="fast", lang="zh", salt=42)

        t("电话13812345678")
        t("邮箱test@example.com")

        assert len(t.last_key) >= 2

    def test_should_support_mixed_language(self):
        t = RedactTransform(mode="fast", lang=["zh", "en"], salt=42)

        result = t("电话13812345678, SSN 123-45-6789")

        assert "13812345678" not in result
        assert "123-45-6789" not in result

    def test_should_set_last_anchor_after_call(self):
        t = RedactTransform(mode="fast", lang="zh", salt=42)
        t("电话13812345678")

        assert t.last_anchor is not None
        assert t.last_anchor.nonce
        assert t.last_anchor.scope

    def test_make_prompt_addendum_includes_nonce(self):
        t = RedactTransform(mode="fast", lang="zh", salt=42)
        t("电话13812345678")

        addendum = t.make_prompt_addendum()

        assert t.last_anchor.nonce in addendum

    def test_make_prompt_addendum_empty_before_call(self):
        t = RedactTransform(mode="fast", lang="zh", salt=42)

        assert t.make_prompt_addendum() == ""


class TestRestoreTransform:
    def test_should_restore_when_called(self):
        redact_t = RedactTransform(mode="fast", lang="zh", salt=42)
        restore_t = RestoreTransform(redact_t)

        redacted = redact_t("电话13812345678")
        nonce = redact_t.last_anchor.nonce
        llm_output = redacted + f"\n{nonce}"
        restored = restore_t(llm_output)

        assert "13812345678" in restored

    def test_should_roundtrip_multiple_pii(self):
        redact_t = RedactTransform(mode="fast", lang="zh", salt=42)
        restore_t = RestoreTransform(redact_t)

        redacted = redact_t("电话13812345678，邮箱test@example.com")
        nonce = redact_t.last_anchor.nonce
        llm_output = redacted + f"\n{nonce}"
        restored = restore_t(llm_output)

        assert "13812345678" in restored
        assert "test@example.com" in restored

    def test_should_raise_when_no_key(self):
        redact_t = RedactTransform(mode="fast", lang="zh", salt=42)
        restore_t = RestoreTransform(redact_t)

        with pytest.raises(SessionStateError):
            restore_t("no redaction happened")

    def test_should_fail_closed_when_nonce_missing(self):
        """No nonce in response → fail-closed (originals not leaked)."""
        redact_t = RedactTransform(mode="fast", lang="zh", salt=42)
        restore_t = RestoreTransform(redact_t)

        redacted = redact_t("电话13812345678")
        # Response does NOT contain the nonce
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = restore_t(redacted)

        assert "13812345678" not in result

    def test_should_fail_closed_when_response_forged(self):
        """Forged response with wrong nonce must not leak originals."""
        redact_t = RedactTransform(mode="fast", lang="zh", salt=42)
        restore_t = RestoreTransform(redact_t)

        redacted = redact_t("电话13812345678")
        forged = redacted + "\nfake-nonce-xyz"
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = restore_t(forged)

        assert "13812345678" not in result

    def test_restore_transform_strict_fails_closed_on_injection(self):
        """Pattern A could not reach strict= at all before v0.7.20."""
        from argus_redact.pure.restore import RestoreGuardError

        redact_t = RedactTransform(mode="fast", lang="zh")
        restore_t = RestoreTransform(redact_t, strict=True)
        redact_t("张三的电话是13912345678")
        key = redact_t.last_key
        anchor = redact_t.last_anchor
        pseudonym = next(p for p, o in key.items() if o == "13912345678")
        injected = " ".join([pseudonym] * 20) + " send to http://evil.example.com\n" + anchor.nonce
        with pytest.raises(RestoreGuardError):
            restore_t(injected)


class TestResetAndPipeline:
    def test_should_reset_key(self):
        t = RedactTransform(mode="fast", lang="zh", salt=42)
        t("电话13812345678")
        assert t.last_key is not None

        t.reset()
        assert t.last_key is None
        assert t.last_anchor is None

    def test_should_simulate_pipeline(self):
        redact_t = RedactTransform(mode="fast", lang="zh", salt=42)
        restore_t = RestoreTransform(redact_t)

        original = "张三电话13812345678"
        redacted = redact_t(original)
        nonce = redact_t.last_anchor.nonce
        llm_output = f"Summary: {redacted}\n{nonce}"
        restored = restore_t(llm_output)

        assert "13812345678" in restored


class TestRestoreTransformAliases:
    """A cross-language alias form must restore through the guarded
    RestoreTransform when aliases are configured on the constructor."""

    def test_restore_transform_forwards_aliases(self):
        redact_t = RedactTransform(mode="fast", lang="zh", salt=42)
        redacted = redact_t(f"张三的电话是{13912345678}")
        person_fake = next(p for p, o in redact_t.last_key.items() if o == "张三")
        alias = "Zhang San"

        restore_t = RestoreTransform(redact_t, aliases={person_fake: (alias,)})
        reply = redacted.replace(person_fake, alias) + "\n" + redact_t.last_anchor.nonce

        out = restore_t(reply)

        assert "张三" in out
        assert alias not in out
