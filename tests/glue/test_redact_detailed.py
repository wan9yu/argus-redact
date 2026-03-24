"""Tests for redact() with detailed=True — returns detection metadata."""

from argus_redact import redact


class TestDetailedMode:
    def test_should_return_3_tuple_when_detailed_true(self):
        result = redact("电话13812345678", detailed=True, seed=42, mode="fast")

        assert len(result) == 3

    def test_should_return_2_tuple_when_detailed_false(self):
        result = redact("电话13812345678", seed=42, mode="fast")

        assert len(result) == 2

    def test_should_include_entities_in_details(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")

        assert "entities" in details
        assert len(details["entities"]) >= 1

    def test_should_include_entity_fields(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")

        entity = details["entities"][0]
        assert "original" in entity
        assert "replacement" in entity
        assert "type" in entity
        assert "start" in entity
        assert "end" in entity
        assert "confidence" in entity

    def test_should_include_stats_in_details(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")

        assert "stats" in details
        assert "total" in details["stats"]
        assert details["stats"]["total"] >= 1

    def test_should_show_correct_entity_info(self):
        _, key, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")

        entity = details["entities"][0]
        assert entity["original"] == "13812345678"
        assert entity["replacement"] in key
        assert entity["type"] == "phone"

    def test_should_return_empty_entities_when_no_pii(self):
        _, _, details = redact("今天天气不错", detailed=True, seed=42, mode="fast")

        assert details["entities"] == []
        assert details["stats"]["total"] == 0

    def test_should_show_multiple_entities(self):
        text = "电话13812345678，邮箱test@example.com"
        _, _, details = redact(text, detailed=True, seed=42, mode="fast")

        assert len(details["entities"]) == 2
        assert details["stats"]["total"] == 2
        types = {e["type"] for e in details["entities"]}
        assert "phone" in types
        assert "email" in types
