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
        assert "layer" in entity
        assert "start" in entity
        assert "end" in entity
        assert "confidence" in entity

    def test_should_tag_regex_as_layer_1(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")

        entity = details["entities"][0]
        assert entity["layer"] == 1

    def test_should_include_layer_counts_in_stats(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")

        stats = details["stats"]
        assert "layer_1" in stats
        assert "layer_2" in stats
        assert "layer_3" in stats
        assert stats["layer_1"] >= 1
        assert stats["layer_2"] == 0
        assert stats["layer_3"] == 0

    def test_should_include_duration_ms_in_stats(self):
        _, _, details = redact("电话13812345678", detailed=True, seed=42, mode="fast")

        stats = details["stats"]
        assert "duration_ms" in stats
        assert stats["duration_ms"] >= 0
        assert "layer_1_ms" in stats
        assert stats["layer_1_ms"] >= 0

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
