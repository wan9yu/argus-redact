"""Tests for semantic detection adapter — using mock Ollama."""

from unittest.mock import MagicMock

import pytest

from argus_redact._types import NEREntity
from argus_redact.impure.semantic import SemanticAdapter, detect_semantic


class TestSemanticAdapterProtocol:
    def test_should_define_detect_method(self):
        adapter = SemanticAdapter()

        with pytest.raises(NotImplementedError):
            adapter.detect("any text")


class TestDetectSemantic:
    def _make_mock_adapter(self, entities):
        adapter = MagicMock(spec=SemanticAdapter)
        adapter.detect.return_value = entities
        return adapter

    def test_should_return_entities_when_adapter_finds_them(self):
        expected = [
            NEREntity(text="那个地方", type="location", start=6, end=10, confidence=0.7),
        ]
        adapter = self._make_mock_adapter(expected)

        results = detect_semantic("老王说他在那个地方见了人", adapter=adapter)

        assert len(results) == 1
        assert results[0].text == "那个地方"
        assert results[0].type == "location"

    def test_should_return_empty_when_no_implicit_pii(self):
        adapter = self._make_mock_adapter([])

        results = detect_semantic("今天天气不错", adapter=adapter)

        assert results == []

    def test_should_return_empty_when_text_is_empty(self):
        adapter = self._make_mock_adapter([])

        results = detect_semantic("", adapter=adapter)

        assert results == []

    def test_should_filter_below_min_confidence(self):
        entities = [
            NEREntity(text="那件事", type="event", start=0, end=3, confidence=0.3),
            NEREntity(text="那个地方", type="location", start=5, end=9, confidence=0.7),
        ]
        adapter = self._make_mock_adapter(entities)

        results = detect_semantic("那件事在那个地方发生", adapter=adapter, min_confidence=0.5)

        assert len(results) == 1
        assert results[0].text == "那个地方"
