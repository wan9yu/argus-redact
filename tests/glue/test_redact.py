"""Tests for redact() glue function — the public API."""

import pytest
from argus_redact import redact, restore

from tests.conftest import parametrize_examples


class TestRedactBasic:
    def test_should_remove_phone_when_text_contains_phone(self):
        redacted, key = redact("电话13812345678", seed=42, mode="fast")

        assert "13812345678" not in redacted
        assert "13812345678" in key.values()

    def test_should_remove_id_when_text_contains_id(self):
        redacted, key = redact("身份证110101199003074610", seed=42, mode="fast")

        assert "110101199003074610" not in redacted

    def test_should_remove_email_when_text_contains_email(self):
        redacted, key = redact("邮箱zhang@example.com", seed=42, mode="fast")

        assert "zhang@example.com" not in redacted

    def test_should_return_unchanged_when_no_pii(self):
        text = "今天天气不错"

        redacted, key = redact(text, seed=42, mode="fast")

        assert redacted == text
        assert key == {}

    def test_should_return_empty_when_text_is_empty(self):
        redacted, key = redact("", seed=42, mode="fast")

        assert redacted == ""
        assert key == {}

    def test_should_remove_all_when_multiple_pii_types(self):
        text = "电话13812345678，邮箱test@example.com"

        redacted, key = redact(text, seed=42, mode="fast")

        assert "13812345678" not in redacted
        assert "test@example.com" not in redacted
        assert len(key) == 2


class TestRedactRoundtrip:
    @parametrize_examples("redact_roundtrip.json")
    def test_should_recover_pii_when_redact_then_restore(self, example):
        original = example["input"]

        redacted, key = redact(original, seed=42, mode="fast")

        if example["pii_values"]:
            for pii in example["pii_values"]:
                assert (
                    pii not in redacted
                ), f"PII '{pii}' still in redacted text: {example['description']}"
            restored = restore(redacted, key)
            for pii in example["pii_values"]:
                assert pii in restored, f"PII '{pii}' not recovered: {example['description']}"
        else:
            assert redacted == original
            assert key == {}


class TestRedactSeedDeterminism:
    def test_should_produce_same_output_when_same_seed(self):
        text = "电话13812345678"

        r1 = redact(text, seed=42, mode="fast")
        r2 = redact(text, seed=42, mode="fast")

        assert r1 == r2


class TestRedactKeyReuse:
    def test_should_grow_key_when_new_entity_with_existing_key(self):
        _, key = redact("电话13812345678", seed=42, mode="fast")
        size1 = len(key)

        _, key = redact("邮箱test@example.com", seed=42, mode="fast", key=key)

        assert len(key) > size1

    def test_should_keep_same_size_when_same_entity_with_existing_key(self):
        _, key1 = redact("电话13812345678", seed=42, mode="fast")

        _, key2 = redact("再说一次13812345678", seed=42, mode="fast", key=key1)

        assert len(key2) == len(key1)


class TestRedactMode:
    def test_should_raise_when_invalid_mode(self):
        with pytest.raises(ValueError):
            redact("text", mode="invalid")

    def test_should_redact_when_fast_mode(self):
        redacted, key = redact("13812345678", seed=42, mode="fast")

        assert "13812345678" not in redacted


class TestRedactTypeErrors:
    def test_should_raise_type_error_when_text_is_not_string(self):
        with pytest.raises(TypeError):
            redact(123)
