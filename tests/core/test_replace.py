"""Tests for replacer — converts pattern matches to redacted text + key."""

from argus_redact.pure.replacer import replace
from tests.conftest import make_match


class TestReplaceBasic:
    """Core replacement behavior."""

    def test_should_redact_phone_when_single_phone_entity(self):
        entities = [make_match("13812345678", "phone", 3)]
        text = "电话是13812345678"

        redacted, key = replace(text, entities, seed=42)

        assert "13812345678" not in redacted
        assert len(key) == 1
        assert "13812345678" in key.values()

    def test_should_use_pseudonym_when_entity_is_person(self):
        entities = [make_match("张三", "person", 0)]

        redacted, key = replace("张三说了话", entities, seed=42)

        assert "张三" not in redacted
        assert redacted.endswith("说了话")
        assert list(key.keys())[0].startswith("P-")

    def test_should_redact_all_when_multiple_entity_types(self):
        entities = [
            make_match("张三", "person", 0),
            make_match("13812345678", "phone", 6),
        ]

        redacted, key = replace("张三的电话是13812345678", entities, seed=42)

        assert "张三" not in redacted
        assert "13812345678" not in redacted
        assert len(key) == 2

    def test_should_use_same_pseudonym_when_same_entity_appears_twice(self):
        entities = [
            make_match("张三", "person", 0),
            make_match("张三", "person", 3),
        ]

        redacted, key = replace("张三和张三", entities, seed=42)

        person_entries = {k: v for k, v in key.items() if v == "张三"}
        assert len(person_entries) == 1


class TestReplaceStrategies:
    """Different entity types use different default strategies."""

    def test_should_use_pseudonym_prefix_when_person(self):
        entities = [make_match("张三", "person", 0)]

        _, key = replace("张三", entities, seed=42)

        assert list(key.keys())[0].startswith("P-")

    def test_should_mask_with_stars_when_phone(self):
        entities = [make_match("13812345678", "phone", 0)]

        _, key = replace("13812345678", entities, seed=42)

        replacement = list(key.keys())[0]
        assert "138" in replacement
        assert "5678" in replacement
        assert "*" in replacement

    def test_should_use_remove_label_when_id_number(self):
        entities = [make_match("110101199003074610", "id_number", 0)]

        _, key = replace("110101199003074610", entities, seed=42)

        replacement = list(key.keys())[0]
        assert replacement.startswith("ID-")  # pseudonym-style for LLM survival

    def test_should_mask_with_domain_when_email(self):
        entities = [make_match("zhang@example.com", "email", 0)]

        _, key = replace("zhang@example.com", entities, seed=42)

        replacement = list(key.keys())[0]
        assert "@" in replacement or "*" in replacement

    def test_should_mask_prefix_suffix_when_bank_card(self):
        entities = [make_match("4111111111111111", "bank_card", 0)]

        _, key = replace("4111111111111111", entities, seed=42)

        replacement = list(key.keys())[0]
        assert replacement.startswith("411")
        assert replacement.endswith("1111")
        assert "*" in replacement


class TestReplaceRightToLeft:
    """Replacement must work right-to-left to preserve offsets."""

    def test_should_preserve_surrounding_text_when_entities_in_middle(self):
        entities = [
            make_match("张三", "person", 1),
            make_match("李四", "person", 4),
        ]

        redacted, key = replace("A张三B李四C", entities, seed=42)

        assert "张三" not in redacted
        assert "李四" not in redacted
        assert redacted.startswith("A")
        assert redacted.endswith("C")


class TestReplaceSeedDeterminism:
    """Same seed + same input = same output."""

    def test_should_produce_same_output_when_same_seed(self):
        entities = [make_match("张三", "person", 0)]

        r1 = replace("张三说话", entities, seed=42)
        r2 = replace("张三说话", entities, seed=42)

        assert r1 == r2

    def test_should_produce_different_output_when_different_seeds(self):
        entities = [make_match("张三", "person", 0)]

        r1 = replace("张三说话", entities, seed=42)
        r2 = replace("张三说话", entities, seed=99)

        assert r1[0] != r2[0]
        assert r1[1] != r2[1]


class TestReplaceEdgeCases:
    """Edge cases."""

    def test_should_return_original_when_no_entities(self):
        redacted, key = replace("普通文本", [], seed=42)

        assert redacted == "普通文本"
        assert key == {}

    def test_should_return_empty_when_text_is_empty(self):
        redacted, key = replace("", [], seed=42)

        assert redacted == ""
        assert key == {}

    def test_should_redact_when_entity_spans_entire_text(self):
        entities = [make_match("AB", "person", 0)]

        redacted, key = replace("AB", entities, seed=42)

        assert "AB" not in redacted
        assert len(key) == 1

    def test_should_reuse_existing_pseudonym_when_key_provided(self):
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

    def test_should_assign_unique_labels_when_two_id_numbers(self):
        entities = [
            make_match("110101199003074610", "id_number", 0),
            make_match("220102198805061234", "id_number", 19),
        ]

        _, key = replace("110101199003074610,220102198805061234", entities, seed=42)

        assert len(key) == 2
        assert len(set(key.keys())) == 2
