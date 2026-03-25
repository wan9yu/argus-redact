"""Tests for FastAPI integration."""

import json

from argus_redact.integrations.fastapi_middleware import (
    redact_body,
    restore_body,
)


class TestRedactBody:
    def test_should_redact_text_field(self):
        body = {"text": "电话13812345678"}

        redacted, key = redact_body(body, mode="fast", lang="zh", seed=42)

        assert "13812345678" not in redacted["text"]
        assert key is not None

    def test_should_redact_custom_field(self):
        body = {"content": "电话13812345678"}

        redacted, key = redact_body(
            body,
            field="content",
            mode="fast",
            lang="zh",
            seed=42,
        )

        assert "13812345678" not in redacted["content"]

    def test_should_preserve_other_fields(self):
        body = {"text": "电话13812345678", "model": "gpt-4o"}

        redacted, key = redact_body(body, mode="fast", lang="zh", seed=42)

        assert redacted["model"] == "gpt-4o"

    def test_should_return_unchanged_when_no_text_field(self):
        body = {"model": "gpt-4o"}

        redacted, key = redact_body(body, mode="fast", lang="zh", seed=42)

        assert redacted == body
        assert key == {}

    def test_should_handle_messages_array(self):
        body = {
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "电话13812345678"},
            ]
        }

        redacted, key = redact_body(
            body,
            field="messages",
            mode="fast",
            lang="zh",
            seed=42,
        )

        assert "13812345678" not in json.dumps(redacted, ensure_ascii=False)
        assert key is not None


class TestRestoreBody:
    def test_should_restore_text_field(self):
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", seed=42)
        response = {"result": redacted["text"]}

        restored = restore_body(response, key, field="result")

        assert "13812345678" in restored["result"]

    def test_should_restore_string_response(self):
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", seed=42)

        restored_text = restore_body(redacted["text"], key)

        assert "13812345678" in restored_text


class TestRoundtrip:
    def test_should_roundtrip_full_flow(self):
        body = {"text": "张三电话13812345678，邮箱zhang@test.com"}

        redacted, key = redact_body(body, mode="fast", lang="zh", seed=42)

        assert "13812345678" not in redacted["text"]
        assert "zhang@test.com" not in redacted["text"]

        response = {"result": redacted["text"]}
        restored = restore_body(response, key, field="result")

        assert "13812345678" in restored["result"]
        assert "zhang@test.com" in restored["result"]
