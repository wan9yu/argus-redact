"""Tests for entity merger — dedup overlapping spans from multiple layers."""

from argus_redact._types import PatternMatch
from argus_redact.pure.merger import merge_entities


def _m(text, type, start, end=None, confidence=1.0):
    if end is None:
        end = start + len(text)
    return PatternMatch(text=text, type=type, start=start, end=end, confidence=confidence)


class TestMergeNoOverlap:
    """Non-overlapping entities should all be kept."""

    def test_should_keep_all_when_no_overlap(self):
        entities = [
            _m("张三", "person", 0),
            _m("13812345678", "phone", 5),
        ]

        result = merge_entities(entities)

        assert len(result) == 2

    def test_should_return_sorted_by_position(self):
        entities = [
            _m("13812345678", "phone", 10),
            _m("张三", "person", 0),
        ]

        result = merge_entities(entities)

        assert result[0].start < result[1].start

    def test_should_return_empty_when_empty_input(self):
        result = merge_entities([])

        assert result == []

    def test_should_return_single_when_one_entity(self):
        entities = [_m("张三", "person", 0)]

        result = merge_entities(entities)

        assert len(result) == 1


class TestMergeExactOverlap:
    """Same span detected by multiple layers."""

    def test_should_keep_higher_confidence_when_exact_overlap(self):
        entities = [
            _m("张三", "person", 0, 2, confidence=1.0),
            _m("张三", "person", 0, 2, confidence=0.85),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].confidence == 1.0

    def test_should_keep_higher_confidence_when_ner_wins(self):
        entities = [
            _m("张三", "person", 0, 2, confidence=0.5),
            _m("张三", "person", 0, 2, confidence=0.95),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_should_dedup_when_identical(self):
        entities = [
            _m("张三", "person", 0, 2, confidence=0.9),
            _m("张三", "person", 0, 2, confidence=0.9),
        ]

        result = merge_entities(entities)

        assert len(result) == 1


class TestMergeContainment:
    """Entity A contains entity B — keep only A."""

    def test_should_keep_longer_when_one_contains_other(self):
        entities = [
            _m("三里屯的星巴克", "location", 0, 7, confidence=0.8),
            _m("星巴克", "organization", 4, 7, confidence=0.9),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].text == "三里屯的星巴克"

    def test_should_keep_longer_when_inner_has_higher_confidence(self):
        entities = [
            _m("北京市朝阳区", "location", 0, 6, confidence=0.7),
            _m("朝阳区", "location", 3, 6, confidence=0.95),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].text == "北京市朝阳区"


class TestMergePartialOverlap:
    """Partially overlapping spans — keep the longer one."""

    def test_should_keep_longer_when_partial_overlap(self):
        entities = [
            _m("张三丰", "person", 0, 3, confidence=0.8),
            _m("三丰集团", "organization", 1, 5, confidence=0.7),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].text == "三丰集团"  # longer span

    def test_should_keep_higher_confidence_when_same_length_overlap(self):
        entities = [
            _m("AB", "person", 0, 2, confidence=0.9),
            _m("BC", "person", 1, 3, confidence=0.8),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].text == "AB"


class TestMergeComplexScenarios:
    """Real-world-like combinations."""

    def test_should_handle_regex_and_ner_together(self):
        entities = [
            _m("13812345678", "phone", 6, 17, confidence=1.0),  # regex
            _m("张三", "person", 0, 2, confidence=0.85),  # NER
        ]

        result = merge_entities(entities)

        assert len(result) == 2
        types = {r.type for r in result}
        assert types == {"phone", "person"}

    def test_should_handle_multiple_overlaps_in_sequence(self):
        entities = [
            _m("张三", "person", 0, 2, confidence=0.9),
            _m("张三", "person", 0, 2, confidence=0.85),
            _m("13812345678", "phone", 5, 16, confidence=1.0),
            _m("李四", "person", 20, 22, confidence=0.9),
            _m("李四", "person", 20, 22, confidence=0.8),
        ]

        result = merge_entities(entities)

        assert len(result) == 3
        texts = {r.text for r in result}
        assert texts == {"张三", "13812345678", "李四"}

    def test_should_handle_adjacent_entities(self):
        entities = [
            _m("张三", "person", 0, 2, confidence=0.9),
            _m("李四", "person", 2, 4, confidence=0.9),
        ]

        result = merge_entities(entities)

        assert len(result) == 2
