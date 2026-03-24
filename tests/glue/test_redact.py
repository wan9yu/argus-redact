"""Tests for redact() glue function — the public API."""

import pytest

from argus_redact import redact, restore
from tests.conftest import PHONE_MOBILE, ID_VALID, EMAIL_SIMPLE


class TestRedactBasic:
    """Core redact behavior with mode='fast' (regex only)."""

    def test_phone_redacted(self):
        redacted, key = redact(f"电话{PHONE_MOBILE}", seed=42, mode="fast")
        assert PHONE_MOBILE not in redacted
        assert PHONE_MOBILE in key.values()

    def test_id_number_redacted(self):
        redacted, key = redact(f"身份证{ID_VALID}", seed=42, mode="fast")
        assert ID_VALID not in redacted

    def test_email_redacted(self):
        redacted, key = redact(f"邮箱{EMAIL_SIMPLE}", seed=42, mode="fast")
        assert EMAIL_SIMPLE not in redacted

    def test_no_pii(self):
        text = "今天天气不错"
        redacted, key = redact(text, seed=42, mode="fast")
        assert redacted == text
        assert key == {}

    def test_empty_text(self):
        redacted, key = redact("", seed=42, mode="fast")
        assert redacted == ""
        assert key == {}

    def test_multiple_pii_types(self):
        text = f"电话{PHONE_MOBILE}，邮箱test@example.com"
        redacted, key = redact(text, seed=42, mode="fast")
        assert PHONE_MOBILE not in redacted
        assert "test@example.com" not in redacted
        assert len(key) == 2


class TestRedactRoundtrip:
    """redact -> restore must recover original PII."""

    def test_phone_roundtrip(self):
        original = f"张三的电话是{PHONE_MOBILE}"
        redacted, key = redact(original, seed=42, mode="fast")
        restored = restore(redacted, key)
        assert PHONE_MOBILE in restored

    def test_multiple_pii_roundtrip(self):
        original = f"电话{PHONE_MOBILE}，邮箱test@example.com"
        redacted, key = redact(original, seed=42, mode="fast")
        restored = restore(redacted, key)
        assert PHONE_MOBILE in restored
        assert "test@example.com" in restored

    def test_id_roundtrip(self):
        original = f"身份证号{ID_VALID}ok"
        redacted, key = redact(original, seed=42, mode="fast")
        restored = restore(redacted, key)
        assert ID_VALID in restored


class TestRedactSeedDeterminism:
    """Same seed + same input = same output."""

    def test_deterministic(self):
        text = f"电话{PHONE_MOBILE}"
        r1 = redact(text, seed=42, mode="fast")
        r2 = redact(text, seed=42, mode="fast")
        assert r1 == r2

    def test_different_seeds_differ(self):
        text = f"电话{PHONE_MOBILE}"
        r1 = redact(text, seed=42, mode="fast")
        r2 = redact(text, seed=99, mode="fast")
        assert PHONE_MOBILE not in r1[0]
        assert PHONE_MOBILE not in r2[0]


class TestRedactKeyReuse:
    """Passing key= preserves existing mappings."""

    def test_key_grows(self):
        _, key = redact(f"电话{PHONE_MOBILE}", seed=42, mode="fast")
        size1 = len(key)
        _, key = redact("邮箱test@example.com", seed=42, mode="fast", key=key)
        assert len(key) > size1

    def test_same_entity_reuses_mapping(self):
        _, key1 = redact(f"电话{PHONE_MOBILE}", seed=42, mode="fast")
        _, key2 = redact(f"再说一次{PHONE_MOBILE}", seed=42, mode="fast", key=key1)
        assert len(key2) == len(key1)


class TestRedactLang:
    """Language parameter."""

    def test_default_lang_zh(self):
        redacted, key = redact(f"电话{PHONE_MOBILE}", seed=42, mode="fast")
        assert PHONE_MOBILE not in redacted

    def test_lang_zh_explicit(self):
        redacted, key = redact(f"电话{PHONE_MOBILE}", seed=42, mode="fast", lang="zh")
        assert PHONE_MOBILE not in redacted


class TestRedactMode:
    """Mode parameter validation."""

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError):
            redact("text", mode="invalid")

    def test_fast_mode(self):
        redacted, key = redact(PHONE_MOBILE, seed=42, mode="fast")
        assert PHONE_MOBILE not in redacted


class TestRedactTypeErrors:
    """Input validation."""

    def test_non_string_text(self):
        with pytest.raises(TypeError):
            redact(123)
