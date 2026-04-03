"""Tests for structured JSON redaction with paths parameter."""

from argus_redact.structured import redact_json, restore_json


class TestRedactJsonPaths:
    def test_should_redact_only_specified_paths(self):
        data = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "张三的手机13812345678"},
            ],
        }

        result, key = redact_json(data, paths=["messages[*].content"], mode="fast")

        assert result["model"] == "gpt-4o"  # untouched
        assert result["messages"][0]["role"] == "system"  # untouched
        assert "13812345678" not in result["messages"][1]["content"]  # redacted
        assert len(key) >= 1

    def test_should_redact_nested_path(self):
        data = {"user": {"name": "张三", "phone": "13812345678", "id": 123}}

        result, key = redact_json(data, paths=["user.phone"], mode="fast")

        assert result["user"]["name"] == "张三"  # untouched
        assert "13812345678" not in result["user"]["phone"]  # redacted
        assert result["user"]["id"] == 123  # untouched

    def test_should_redact_all_when_no_paths(self):
        data = {"name": "张三", "phone": "13812345678"}

        result, key = redact_json(data, mode="fast")

        # Without paths, all strings are redacted (existing behavior)
        assert "13812345678" not in str(result)

    def test_should_handle_wildcard_in_list(self):
        data = {
            "items": [
                {"text": "手机13812345678", "type": "message"},
                {"text": "身份证110101199003074610", "type": "id"},
            ]
        }

        result, key = redact_json(data, paths=["items[*].text"], mode="fast")

        assert result["items"][0]["type"] == "message"  # untouched
        assert result["items"][1]["type"] == "id"  # untouched
        assert "13812345678" not in result["items"][0]["text"]  # redacted
        assert "110101199003074610" not in result["items"][1]["text"]  # redacted

    def test_should_handle_multiple_paths(self):
        data = {
            "sender": "张三",
            "receiver": "李四",
            "content": "手机13812345678",
            "timestamp": "2026-01-01",
        }

        result, key = redact_json(data, paths=["sender", "content"], mode="fast")

        assert result["receiver"] == "李四"  # untouched
        assert result["timestamp"] == "2026-01-01"  # untouched
        assert "13812345678" not in result["content"]  # redacted

    def test_should_restore_paths_redacted_json(self):
        data = {"messages": [{"role": "user", "content": "手机13812345678"}]}

        redacted, key = redact_json(data, paths=["messages[*].content"], mode="fast", seed=42)
        restored = restore_json(redacted, key)

        assert "13812345678" in restored["messages"][0]["content"]

    def test_should_handle_nonexistent_path(self):
        data = {"name": "张三"}

        result, key = redact_json(data, paths=["nonexistent.field"], mode="fast")

        assert result["name"] == "张三"  # untouched, path doesn't exist
        assert len(key) == 0
