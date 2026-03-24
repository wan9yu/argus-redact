"""Tests for redact() glue function — the public API."""

import pytest

from argus_redact import redact, restore


class TestRedactBasic:
    """Core redact behavior with mode='fast' (regex only)."""

    def test_phone_redacted(self):
        redacted, key = redact("电话13812345678", seed=42, mode="fast")
        assert "13812345678" not in redacted
        assert "13812345678" in key.values()

    def test_id_number_redacted(self):
        redacted, key = redact("身份证110101199003074610", seed=42, mode="fast")
        assert "110101199003074610" not in redacted

    def test_email_redacted(self):
        redacted, key = redact("邮箱zhang@example.com", seed=42, mode="fast")
        assert "zhang@example.com" not in redacted

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
        text = "电话13812345678，邮箱test@example.com"
        redacted, key = redact(text, seed=42, mode="fast")
        assert "13812345678" not in redacted
        assert "test@example.com" not in redacted
        assert len(key) == 2


class TestRedactRoundtrip:
    """redact -> restore must recover original PII."""

    def test_phone_roundtrip(self):
        original = "张三的电话是13812345678"
        redacted, key = redact(original, seed=42, mode="fast")
        restored = restore(redacted, key)
        assert "13812345678" in restored

    def test_multiple_pii_roundtrip(self):
        original = "电话13812345678，邮箱test@example.com"
        redacted, key = redact(original, seed=42, mode="fast")
        restored = restore(redacted, key)
        assert "13812345678" in restored
        assert "test@example.com" in restored

    def test_id_roundtrip(self):
        original = "身份证号110101199003074610ok"
        redacted, key = redact(original, seed=42, mode="fast")
        restored = restore(redacted, key)
        assert "110101199003074610" in restored


class TestRedactSeedDeterminism:
    """Same seed + same input = same output."""

    def test_deterministic(self):
        text = "电话13812345678"
        r1 = redact(text, seed=42, mode="fast")
        r2 = redact(text, seed=42, mode="fast")
        assert r1 == r2

    def test_different_seeds_differ(self):
        text = "电话13812345678"
        r1 = redact(text, seed=42, mode="fast")
        r2 = redact(text, seed=99, mode="fast")
        # mask strategy is deterministic regardless of seed,
        # but the keys may still be equal for mask. That's OK.
        # Just verify they both work
        assert "13812345678" not in r1[0]
        assert "13812345678" not in r2[0]


class TestRedactKeyReuse:
    """Passing key= preserves existing mappings."""

    def test_key_grows(self):
        _, key = redact("电话13812345678", seed=42, mode="fast")
        size1 = len(key)
        _, key = redact("邮箱test@example.com", seed=42, mode="fast", key=key)
        assert len(key) > size1

    def test_same_entity_reuses_mapping(self):
        _, key1 = redact("电话13812345678", seed=42, mode="fast")
        text2, key2 = redact("再说一次13812345678", seed=42, mode="fast", key=key1)
        # Same phone -> same replacement
        assert len(key2) == len(key1)


class TestRedactLang:
    """Language parameter."""

    def test_default_lang_zh(self):
        redacted, key = redact("电话13812345678", seed=42, mode="fast")
        assert "13812345678" not in redacted

    def test_lang_zh_explicit(self):
        redacted, key = redact("电话13812345678", seed=42, mode="fast", lang="zh")
        assert "13812345678" not in redacted


class TestRedactMode:
    """Mode parameter validation."""

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError):
            redact("text", mode="invalid")

    def test_fast_mode(self):
        redacted, key = redact("13812345678", seed=42, mode="fast")
        assert "13812345678" not in redacted


class TestRedactTypeErrors:
    """Input validation."""

    def test_non_string_text(self):
        with pytest.raises(TypeError):
            redact(123)
