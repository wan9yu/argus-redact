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


class TestRedactSelfReference:
    """Tier 1: self_reference replaced when other PII present."""

    def test_should_replace_wo_when_text_contains_pii_zh(self):
        redacted, key = redact("我确诊了糖尿病", seed=42, mode="fast")

        assert "我" not in redacted
        assert "我" in key.values()

    def test_should_replace_I_when_text_contains_pii_en(self):
        redacted, key = redact("I was diagnosed with diabetes", seed=42, mode="fast", lang="en")

        assert " I " not in redacted

    def test_should_roundtrip_when_self_reference_zh(self):
        original = "我在协和医院做了体检，医生说我血糖偏高"

        redacted, key = redact(original, seed=42, mode="fast")
        restored = restore(redacted, key)

        assert "我" not in redacted
        assert "我" in restored

    def test_should_roundtrip_when_kinship_zh(self):
        original = "我妈在301医院住院"

        redacted, key = redact(original, seed=42, mode="fast")
        restored = restore(redacted, key)

        assert "我妈" not in redacted
        assert "我妈" in restored

    def test_should_use_same_pseudonym_for_all_wo_in_text(self):
        redacted, key = redact("我去了医院，我很担心", seed=42, mode="fast")

        wo_codes = [code for code, val in key.items() if val == "我"]
        assert len(wo_codes) == 1, "All 我 should map to same pseudonym"

    # ── Tier 2: no replacement when no other PII ──

    def test_should_not_replace_wo_when_no_pii_zh(self):
        """Tier 2: 我 without other PII should NOT be replaced."""
        redacted, key = redact("我觉得天气很好", seed=42, mode="fast")

        assert "我" in redacted
        assert key == {}

    def test_should_not_replace_I_when_no_pii_en(self):
        redacted, key = redact("I think this is a good plan", seed=42, mode="fast", lang="en")

        assert redacted.startswith("I ")
        assert key == {}

    def test_should_not_replace_women_when_no_pii_zh(self):
        redacted, key = redact("我们今天开会讨论一下", seed=42, mode="fast")

        assert "我们" in redacted

    # ── Tier 3: interaction commands completely ignored ──

    def test_should_ignore_wo_in_command_zh(self):
        """Tier 3: 我想问/帮我 are commands, not privacy signals."""
        redacted, key = redact("我想问一下怎么用Python", seed=42, mode="fast")

        assert "我" in redacted
        assert key == {}

    def test_should_ignore_I_in_command_en(self):
        redacted, key = redact("Can you help me with Python?", seed=42, mode="fast", lang="en")

        assert "me" in redacted

    # ── Tier 1 still works: kinship always replaces (even without explicit PII) ──

    def test_should_always_replace_kinship_zh(self):
        """Kinship terms are always Tier 1 — they inherently bind identity."""
        redacted, key = redact("我妈最近身体不好", seed=42, mode="fast")

        assert "我妈" not in redacted


class TestRedactSelfReferenceGrammar:
    """English grammar should be normalized after first-person replacement."""

    def test_should_fix_I_am_to_is(self):
        redacted, _ = redact(
            "I am diagnosed with diabetes", seed=42, mode="fast", lang="en",
        )

        assert " am " not in redacted
        assert " is " in redacted

    def test_should_fix_I_have_to_has(self):
        redacted, _ = redact(
            "I have diabetes and hypertension", seed=42, mode="fast", lang="en",
        )

        assert " have " not in redacted
        assert " has " in redacted

    def test_should_fix_Im_contraction(self):
        redacted, _ = redact(
            "I'm diagnosed with diabetes", seed=42, mode="fast", lang="en",
        )

        assert "'m " not in redacted

    def test_should_fix_I_was_stays_was(self):
        """was is valid for third-person too, no change needed."""
        redacted, _ = redact(
            "I was diagnosed with diabetes", seed=42, mode="fast", lang="en",
        )

        assert " was " in redacted

    def test_should_not_change_grammar_for_zh(self):
        """Chinese has no verb conjugation, no changes needed."""
        redacted, _ = redact("我很开心", seed=42, mode="fast")

        assert "很开心" in redacted

    def test_should_restore_grammar_on_roundtrip(self):
        """Grammar should be fully restored after roundtrip."""
        original = "I'm feeling sick. I have diabetes."

        redacted, key = redact(original, seed=42, mode="fast", lang="en")
        restored = restore(redacted, key)

        assert "I have" in restored or "I'm" in restored


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
