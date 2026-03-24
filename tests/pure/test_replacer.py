"""Tests for replacer — converts pattern matches to redacted text + key."""

import pytest

from argus_redact._types import PatternMatch
from argus_redact.pure.replacer import replace


class TestReplaceBasic:
    """Core replacement behavior."""

    def test_single_phone(self):
        entities = [PatternMatch("13812345678", "phone", 3, 14)]
        text = "电话是13812345678"
        redacted, key = replace(text, entities, seed=42)
        assert "13812345678" not in redacted
        assert len(key) == 1
        assert "13812345678" in key.values()

    def test_single_person(self):
        entities = [PatternMatch("张三", "person", 0, 2)]
        redacted, key = replace("张三说了话", entities, seed=42)
        assert "张三" not in redacted
        assert redacted.endswith("说了话")
        # person type uses pseudonym strategy by default
        replacement = list(key.keys())[0]
        assert replacement.startswith("P-")

    def test_multiple_entities(self):
        entities = [
            PatternMatch("张三", "person", 0, 2),
            PatternMatch("13812345678", "phone", 6, 17),
        ]
        redacted, key = replace("张三的电话是13812345678", entities, seed=42)
        assert "张三" not in redacted
        assert "13812345678" not in redacted
        assert len(key) == 2

    def test_same_entity_twice(self):
        """Same entity appearing twice gets same pseudonym."""
        entities = [
            PatternMatch("张三", "person", 0, 2),
            PatternMatch("张三", "person", 3, 5),
        ]
        redacted, key = replace("张三和张三", entities, seed=42)
        # Only one key entry for 张三
        person_entries = {k: v for k, v in key.items() if v == "张三"}
        assert len(person_entries) == 1


class TestReplaceStrategies:
    """Different entity types use different default strategies."""

    def test_person_uses_pseudonym(self):
        entities = [PatternMatch("张三", "person", 0, 2)]
        _, key = replace("张三", entities, seed=42)
        replacement = list(key.keys())[0]
        assert replacement.startswith("P-")

    def test_phone_uses_mask(self):
        entities = [PatternMatch("13812345678", "phone", 0, 11)]
        redacted, key = replace("13812345678", entities, seed=42)
        # Default mask: show first 3 + last 4
        replacement = list(key.keys())[0]
        assert "138" in replacement
        assert "5678" in replacement
        assert "*" in replacement

    def test_id_number_uses_remove(self):
        entities = [PatternMatch("110101199003074610", "id_number", 0, 18)]
        _, key = replace("110101199003074610", entities, seed=42)
        replacement = list(key.keys())[0]
        assert "脱敏" in replacement or "REDACTED" in replacement

    def test_email_uses_mask(self):
        entities = [PatternMatch("zhang@example.com", "email", 0, 17)]
        _, key = replace("zhang@example.com", entities, seed=42)
        replacement = list(key.keys())[0]
        assert "@" in replacement or "*" in replacement

    def test_bank_card_uses_mask(self):
        entities = [PatternMatch("4111111111111111", "bank_card", 0, 16)]
        _, key = replace("4111111111111111", entities, seed=42)
        replacement = list(key.keys())[0]
        assert replacement.startswith("411")
        assert replacement.endswith("1111")
        assert "*" in replacement


class TestReplaceRightToLeft:
    """Replacement must work right-to-left to preserve offsets."""

    def test_offsets_preserved(self):
        text = "A张三B李四C"
        entities = [
            PatternMatch("张三", "person", 1, 3),
            PatternMatch("李四", "person", 4, 6),
        ]
        redacted, key = replace(text, entities, seed=42)
        assert "张三" not in redacted
        assert "李四" not in redacted
        assert redacted.startswith("A")
        assert redacted.endswith("C")


class TestReplaceSeedDeterminism:
    """Same seed + same input = same output."""

    def test_deterministic(self):
        entities = [PatternMatch("张三", "person", 0, 2)]
        r1 = replace("张三说话", entities, seed=42)
        r2 = replace("张三说话", entities, seed=42)
        assert r1 == r2

    def test_different_seeds(self):
        entities = [PatternMatch("张三", "person", 0, 2)]
        r1 = replace("张三说话", entities, seed=42)
        r2 = replace("张三说话", entities, seed=99)
        assert r1[0] != r2[0]  # different redacted text
        assert r1[1] != r2[1]  # different key


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
        entities = [PatternMatch("AB", "person", 0, 2)]
        redacted, key = replace("AB", entities, seed=42)
        assert "AB" not in redacted
        assert len(key) == 1

    def test_key_reuse(self):
        """Passing existing key preserves mappings."""
        existing_key = {"P-037": "张三"}
        entities = [
            PatternMatch("张三", "person", 0, 2),
            PatternMatch("李四", "person", 3, 5),
        ]
        redacted, key = replace("张三和李四", entities, seed=42, key=existing_key)
        assert "P-037" in redacted  # reused
        assert key["P-037"] == "张三"
        assert len(key) == 2


class TestReplaceCollisionNumbering:
    """Multiple same-type entities with remove strategy get numbered."""

    def test_two_id_numbers(self):
        entities = [
            PatternMatch("110101199003074610", "id_number", 0, 18),
            PatternMatch("220102198805061234", "id_number", 19, 37),
        ]
        _, key = replace("110101199003074610,220102198805061234", entities, seed=42)
        assert len(key) == 2
        # Keys must be unique
        assert len(set(key.keys())) == 2
