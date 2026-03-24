"""Tests for replacer — converts pattern matches to redacted text + key."""

import pytest

from argus_redact.pure.replacer import replace
from tests.conftest import make_match, PHONE_MOBILE, ID_VALID, EMAIL_SIMPLE, BANK_CARD_VISA


class TestReplaceBasic:
    """Core replacement behavior."""

    def test_single_phone(self):
        entities = [make_match(PHONE_MOBILE, "phone", 3)]
        text = f"电话是{PHONE_MOBILE}"
        redacted, key = replace(text, entities, seed=42)
        assert PHONE_MOBILE not in redacted
        assert len(key) == 1
        assert PHONE_MOBILE in key.values()

    def test_single_person(self):
        entities = [make_match("张三", "person", 0)]
        redacted, key = replace("张三说了话", entities, seed=42)
        assert "张三" not in redacted
        assert redacted.endswith("说了话")
        replacement = list(key.keys())[0]
        assert replacement.startswith("P-")

    def test_multiple_entities(self):
        entities = [
            make_match("张三", "person", 0),
            make_match(PHONE_MOBILE, "phone", 6),
        ]
        redacted, key = replace(f"张三的电话是{PHONE_MOBILE}", entities, seed=42)
        assert "张三" not in redacted
        assert PHONE_MOBILE not in redacted
        assert len(key) == 2

    def test_same_entity_twice(self):
        entities = [
            make_match("张三", "person", 0),
            make_match("张三", "person", 3),
        ]
        redacted, key = replace("张三和张三", entities, seed=42)
        person_entries = {k: v for k, v in key.items() if v == "张三"}
        assert len(person_entries) == 1


class TestReplaceStrategies:
    """Different entity types use different default strategies."""

    def test_person_uses_pseudonym(self):
        entities = [make_match("张三", "person", 0)]
        _, key = replace("张三", entities, seed=42)
        assert list(key.keys())[0].startswith("P-")

    def test_phone_uses_mask(self):
        entities = [make_match(PHONE_MOBILE, "phone", 0)]
        _, key = replace(PHONE_MOBILE, entities, seed=42)
        replacement = list(key.keys())[0]
        assert "138" in replacement
        assert "5678" in replacement
        assert "*" in replacement

    def test_id_number_uses_remove(self):
        entities = [make_match(ID_VALID, "id_number", 0)]
        _, key = replace(ID_VALID, entities, seed=42)
        replacement = list(key.keys())[0]
        assert "脱敏" in replacement or "REDACTED" in replacement

    def test_email_uses_mask(self):
        entities = [make_match(EMAIL_SIMPLE, "email", 0)]
        _, key = replace(EMAIL_SIMPLE, entities, seed=42)
        replacement = list(key.keys())[0]
        assert "@" in replacement or "*" in replacement

    def test_bank_card_uses_mask(self):
        entities = [make_match(BANK_CARD_VISA, "bank_card", 0)]
        _, key = replace(BANK_CARD_VISA, entities, seed=42)
        replacement = list(key.keys())[0]
        assert replacement.startswith("411")
        assert replacement.endswith("1111")
        assert "*" in replacement


class TestReplaceRightToLeft:
    """Replacement must work right-to-left to preserve offsets."""

    def test_offsets_preserved(self):
        text = "A张三B李四C"
        entities = [
            make_match("张三", "person", 1),
            make_match("李四", "person", 4),
        ]
        redacted, key = replace(text, entities, seed=42)
        assert "张三" not in redacted
        assert "李四" not in redacted
        assert redacted.startswith("A")
        assert redacted.endswith("C")


class TestReplaceSeedDeterminism:
    """Same seed + same input = same output."""

    def test_deterministic(self):
        entities = [make_match("张三", "person", 0)]
        r1 = replace("张三说话", entities, seed=42)
        r2 = replace("张三说话", entities, seed=42)
        assert r1 == r2

    def test_different_seeds(self):
        entities = [make_match("张三", "person", 0)]
        r1 = replace("张三说话", entities, seed=42)
        r2 = replace("张三说话", entities, seed=99)
        assert r1[0] != r2[0]
        assert r1[1] != r2[1]


class TestReplaceEdgeCases:
    """Edge cases."""

    def test_no_entities(self):
        redacted, key = replace("普通文本", [], seed=42)
        assert redacted == "普通文本"
        assert key == {}

    def test_empty_text(self):
        redacted, key = replace("", [], seed=42)
        assert redacted == ""
        assert key == {}

    def test_entity_at_boundaries(self):
        entities = [make_match("AB", "person", 0)]
        redacted, key = replace("AB", entities, seed=42)
        assert "AB" not in redacted
        assert len(key) == 1

    def test_key_reuse(self):
        existing_key = {"P-037": "张三"}
        entities = [
            make_match("张三", "person", 0),
            make_match("李四", "person", 3),
        ]
        redacted, key = replace("张三和李四", entities, seed=42, key=existing_key)
        assert "P-037" in redacted
        assert key["P-037"] == "张三"
        assert len(key) == 2


class TestReplaceCollisionNumbering:
    """Multiple same-type entities with remove strategy get numbered."""

    def test_two_id_numbers(self):
        id2 = "220102198805061234"
        entities = [
            make_match(ID_VALID, "id_number", 0),
            make_match(id2, "id_number", 19),
        ]
        _, key = replace(f"{ID_VALID},{id2}", entities, seed=42)
        assert len(key) == 2
        assert len(set(key.keys())) == 2
