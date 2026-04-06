"""Tests for Ollama semantic adapter — mock HTTP calls."""

import json
from unittest.mock import MagicMock, patch

from argus_redact.impure.ollama_adapter import OllamaAdapter


class TestOllamaAdapter:
    def _make_adapter(self, model="qwen2.5:32b", base_url="http://localhost:11434"):
        return OllamaAdapter(model=model, base_url=base_url)

    def _mock_response(self, json_entities):
        """Create a mock HTTP response with LLM JSON output."""
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "response": json.dumps(json_entities, ensure_ascii=False),
        }
        return response

    @patch("argus_redact.impure.ollama_adapter.requests.post")
    def test_should_detect_implicit_location(self, mock_post):
        mock_post.return_value = self._mock_response(
            [
                {"text": "那个地方", "type": "location", "start": 6, "end": 10},
            ]
        )
        adapter = self._make_adapter()

        results = adapter.detect("老王说他在那个地方见了人")

        assert len(results) == 1
        assert results[0].text == "那个地方"
        assert results[0].type == "location"

    @patch("argus_redact.impure.ollama_adapter.requests.post")
    def test_should_detect_nickname(self, mock_post):
        mock_post.return_value = self._mock_response(
            [
                {"text": "老王", "type": "person", "start": 0, "end": 2},
            ]
        )
        adapter = self._make_adapter()

        results = adapter.detect("老王说他上周去了医院")

        assert len(results) == 1
        assert results[0].text == "老王"
        assert results[0].type == "person"

    @patch("argus_redact.impure.ollama_adapter.requests.post")
    def test_should_detect_multiple_implicit_pii(self, mock_post):
        mock_post.return_value = self._mock_response(
            [
                {"text": "老王", "type": "person", "start": 0, "end": 2},
                {"text": "那个地方", "type": "location", "start": 7, "end": 11},
                {"text": "那件事", "type": "event", "start": 13, "end": 16},
            ]
        )
        adapter = self._make_adapter()

        results = adapter.detect("老王说他上周在那个地方聊了那件事")

        assert len(results) == 3

    @patch("argus_redact.impure.ollama_adapter.requests.post")
    def test_should_return_empty_when_no_pii(self, mock_post):
        mock_post.return_value = self._mock_response([])
        adapter = self._make_adapter()

        results = adapter.detect("今天天气真不错")

        assert results == []

    @patch("argus_redact.impure.ollama_adapter.requests.post")
    def test_should_return_empty_when_llm_returns_invalid_json(self, mock_post):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"response": "not valid json ["}
        mock_post.return_value = response
        adapter = self._make_adapter()

        results = adapter.detect("老王说了话")

        assert results == []

    @patch("argus_redact.impure.ollama_adapter.requests.post")
    def test_should_return_empty_when_http_error(self, mock_post):
        mock_post.side_effect = Exception("connection refused")
        adapter = self._make_adapter()

        results = adapter.detect("老王说了话")

        assert results == []

    @patch("argus_redact.impure.ollama_adapter.requests.post")
    def test_should_validate_entity_spans_against_text(self, mock_post):
        mock_post.return_value = self._mock_response(
            [
                {"text": "老王", "type": "person", "start": 0, "end": 2},
                {"text": "不存在的", "type": "person", "start": 50, "end": 54},
            ]
        )
        adapter = self._make_adapter()

        results = adapter.detect("老王说了话")

        assert len(results) == 1
        assert results[0].text == "老王"

    @patch("argus_redact.impure.ollama_adapter.requests.post")
    def test_should_use_custom_model(self, mock_post):
        mock_post.return_value = self._mock_response([])
        adapter = self._make_adapter(model="qwen2.5:7b")

        adapter.detect("测试")

        call_body = mock_post.call_args[1]["json"]
        assert call_body["model"] == "qwen2.5:7b"
