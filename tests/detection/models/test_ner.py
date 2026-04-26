"""Tests for NER adapter — using mock backend."""

from unittest.mock import MagicMock

import pytest

from argus_redact._types import NEREntity
from argus_redact.impure.ner import NERAdapter, detect_ner


class TestNERAdapterProtocol:
    """NERAdapter interface contract."""

    def test_should_define_detect_method(self):
        adapter = NERAdapter()

        with pytest.raises(NotImplementedError):
            adapter.detect("any text")

    def test_should_define_load_method(self):
        adapter = NERAdapter()

        with pytest.raises(NotImplementedError):
            adapter.load()


class TestDetectNER:
    """detect_ner() integration with adapter."""

    def _make_mock_adapter(self, entities: list[NEREntity]):
        adapter = MagicMock(spec=NERAdapter)
        adapter.detect.return_value = entities
        return adapter

    def test_should_return_entities_when_adapter_finds_them(self):
        expected = [
            NEREntity(text="张三", type="person", start=0, end=2, confidence=0.95),
        ]
        adapter = self._make_mock_adapter(expected)

        results = detect_ner("张三去了北京", adapter=adapter)

        assert len(results) == 1
        assert results[0].text == "张三"
        assert results[0].type == "person"
        adapter.detect.assert_called_once_with("张三去了北京")

    def test_should_return_empty_when_no_entities(self):
        adapter = self._make_mock_adapter([])

        results = detect_ner("今天天气不错", adapter=adapter)

        assert results == []

    def test_should_return_multiple_types_when_mixed_entities(self):
        entities = [
            NEREntity(text="张三", type="person", start=0, end=2, confidence=0.95),
            NEREntity(text="阿里巴巴", type="organization", start=3, end=7, confidence=0.90),
            NEREntity(text="杭州", type="location", start=8, end=10, confidence=0.88),
        ]
        adapter = self._make_mock_adapter(entities)

        results = detect_ner("张三在阿里巴巴的杭州总部工作", adapter=adapter)

        types = {r.type for r in results}
        assert types == {"person", "organization", "location"}

    def test_should_filter_below_min_confidence(self):
        entities = [
            NEREntity(text="张三", type="person", start=0, end=2, confidence=0.95),
            NEREntity(text="那个", type="person", start=3, end=5, confidence=0.30),
        ]
        adapter = self._make_mock_adapter(entities)

        results = detect_ner("张三和那个人", adapter=adapter, min_confidence=0.5)

        assert len(results) == 1
        assert results[0].text == "张三"

    def test_should_return_empty_when_text_is_empty(self):
        adapter = self._make_mock_adapter([])

        results = detect_ner("", adapter=adapter)

        assert results == []


class TestNEREntityToPatternMatch:
    """NER results should be convertible for use in replacer."""

    def test_should_convert_to_pattern_match(self):
        entity = NEREntity(text="张三", type="person", start=0, end=2, confidence=0.95)

        match = entity.to_pattern_match()

        assert match.text == "张三"
        assert match.type == "person"
        assert match.start == 0
        assert match.end == 2
        assert match.confidence == 0.95
