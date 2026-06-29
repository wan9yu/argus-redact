"""Tests for FastAPI integration."""

import json

import pytest

from argus_redact.integrations.fastapi_middleware import (
    redact_body,
    restore_body,
)


class TestRedactBody:
    def test_should_redact_text_field(self):
        body = {"text": "电话13812345678"}

        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        assert "13812345678" not in redacted["text"]
        assert key is not None

    def test_should_redact_custom_field(self):
        body = {"content": "电话13812345678"}

        redacted, key = redact_body(
            body,
            field="content",
            mode="fast",
            lang="zh",
            salt=42,
        )

        assert "13812345678" not in redacted["content"]

    def test_should_preserve_other_fields(self):
        body = {"text": "电话13812345678", "model": "gpt-4o"}

        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        assert redacted["model"] == "gpt-4o"

    def test_should_return_unchanged_when_no_text_field(self):
        body = {"model": "gpt-4o"}

        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        assert redacted == body
        assert key == {}

    def test_should_fail_closed_when_field_present_but_not_str(self):
        # A present-but-non-str field must fail CLOSED
        # (raise), not silently return the body un-redacted with an empty key —
        # that fail-open path leaks the PII inside the list/dict.
        body = {"text": ["电话13812345678"]}

        with pytest.raises(TypeError):
            redact_body(body, mode="fast", lang="zh", salt=42)

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
            salt=42,
        )

        assert "13812345678" not in json.dumps(redacted, ensure_ascii=False)
        assert key is not None


class TestMessagesFailClosed:
    """messages branch must fail CLOSED on non-conforming shapes."""

    def test_tool_call_message_raises_typeerror(self):
        """A dict message with no 'content' key (e.g. OpenAI tool-call) raises TypeError."""
        body = {
            "messages": [
                {"role": "assistant", "tool_calls": [{"id": "c1", "function": {"name": "f", "arguments": '{"phone":"13812345678"}'}}]},
            ]
        }
        with pytest.raises(TypeError, match="content"):
            redact_body(body, field="messages", mode="fast", lang="zh", salt=42)

    def test_bare_string_element_raises_typeerror(self):
        """A bare-string element in messages raises TypeError."""
        body = {"messages": ["电话13812345678"]}
        with pytest.raises(TypeError, match="not a dict"):
            redact_body(body, field="messages", mode="fast", lang="zh", salt=42)

    def test_list_content_raises_typeerror(self):
        """A message with list content (multimodal) raises TypeError."""
        body = {
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "电话13812345678"}]},
            ]
        }
        with pytest.raises(TypeError, match="multimodal"):
            redact_body(body, field="messages", mode="fast", lang="zh", salt=42)

    def test_well_formed_messages_still_redact(self):
        """Well-formed [{role, content: str}] messages still redact and round-trip."""
        body = {
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "我的电话是13812345678，邮箱zhang@example.com"},
            ]
        }
        redacted, key = redact_body(body, field="messages", mode="fast", lang="zh", salt=42)
        dumped = json.dumps(redacted, ensure_ascii=False)
        # PII must not appear
        assert "13812345678" not in dumped
        assert "zhang@example.com" not in dumped
        # Same entity aliases survive across messages (shared key)
        assert key

    def test_repeated_pii_gets_one_alias(self):
        """The same PII across multiple messages maps to one alias (shared key)."""
        body = {
            "messages": [
                {"role": "user", "content": "电话13812345678"},
                {"role": "user", "content": "再次确认，电话13812345678"},
            ]
        }
        redacted, key = redact_body(body, field="messages", mode="fast", lang="zh", salt=42)
        # Both redacted content values should have the same replacement token
        c1 = redacted["messages"][0]["content"]
        c2 = redacted["messages"][1]["content"]
        # Key has exactly one entry for the phone
        assert len(key) == 1
        # Restore round-trips
        from argus_redact import restore
        r1 = restore(c1, key)
        r2 = restore(c2, key)
        assert "13812345678" in r1
        assert "13812345678" in r2


class TestRestoreBody:
    def test_should_restore_text_field(self):
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)
        response = {"result": redacted["text"]}

        restored = restore_body(response, key, field="result")

        assert "13812345678" in restored["result"]

    def test_should_restore_string_response(self):
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        restored_text = restore_body(redacted["text"], key)

        assert "13812345678" in restored_text


class TestRoundtrip:
    def test_should_roundtrip_full_flow(self):
        body = {"text": "张三电话13812345678，邮箱zhang@test.com"}

        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        assert "13812345678" not in redacted["text"]
        assert "zhang@test.com" not in redacted["text"]

        response = {"result": redacted["text"]}
        restored = restore_body(response, key, field="result")

        assert "13812345678" in restored["result"]
        assert "zhang@test.com" in restored["result"]
