"""Tests for FastAPI integration."""

import json

import pytest

from argus_redact.compose import make_anchor, prompt_anchor
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
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "function": {"name": "f", "arguments": '{"phone":"13812345678"}'},
                        }
                    ],
                },
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

        r1 = restore(c1, key, guard=False)
        r2 = restore(c2, key, guard=False)
        assert "13812345678" in r1
        assert "13812345678" in r2


class TestRestoreBody:
    def test_should_restore_text_field(self):
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)
        response = {"result": redacted["text"]}

        restored = restore_body(response, key, field="result", guard=False)

        assert "13812345678" in restored["result"]

    def test_should_restore_string_response(self):
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        restored_text = restore_body(redacted["text"], key, guard=False)

        assert "13812345678" in restored_text

    def test_should_fail_closed_when_field_missing(self):
        # A dict response missing the requested field must fail CLOSED
        # (raise), not silently return the response unchanged with an empty
        # security_events list — that false all-clear hides the fact that
        # nothing was restored.
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)
        response = {"answer": redacted["text"]}

        with pytest.raises(TypeError):
            restore_body(response, key, field="result", guard=False)

    def test_should_fail_closed_when_field_present_but_not_str(self):
        body = {"text": "电话13812345678"}
        _, key = redact_body(body, mode="fast", lang="zh", salt=42)
        response = {"result": 123}

        with pytest.raises(TypeError):
            restore_body(response, key, field="result", guard=False)

    def test_should_return_unchanged_when_key_empty(self):
        # Positive control: an empty key means nothing to restore — this
        # short-circuit must keep working unchanged after the fix above.
        response = {"result": "no PII here"}

        restored = restore_body(response, {}, field="result", guard=False)

        assert restored == response

    def test_should_fail_closed_when_dict_field_omitted(self):
        # A dict response with NO field selector was silently returned unchanged
        # with an empty security_events list — a false all-clear that hides the
        # fact that nothing was restored. It must fail CLOSED (raise) instead.
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)
        response = {"result": redacted["text"]}

        with pytest.raises(TypeError):
            restore_body(response, key, guard=False)

    def test_should_fail_closed_when_response_is_neither_str_nor_dict(self):
        # A list/other shape can carry no restorable string — fail CLOSED rather
        # than hand it straight back as an implied all-clear.
        body = {"text": "电话13812345678"}
        _, key = redact_body(body, mode="fast", lang="zh", salt=42)

        with pytest.raises(TypeError):
            restore_body(["not", "a", "string"], key, guard=False)

    def test_empty_key_detailed_returns_outcome_key(self):
        # Shape parity with guarded_restore: the detailed no-op return must carry
        # an "outcome" key too, not just "security_events".
        response = {"result": "no PII here"}

        _restored, details = restore_body(response, {}, field="result", guard=False, detailed=True)

        assert "outcome" in details

    def test_restore_body_forwards_aliases(self):
        # A cross-language alias form must restore through restore_body when
        # aliases= is supplied (and not without it).
        key = {"P-1": "张三"}
        response = {"result": "P-1 and Zhang San"}
        aliases = {"P-1": ("Zhang San",)}

        restored = restore_body(response, key, field="result", guard=False, aliases=aliases)

        assert restored["result"] == "张三 and 张三"

    def test_restore_body_rejects_malformed_aliases(self):
        # A non-empty key is required: restore_body short-circuits on an
        # empty key before ever reaching guarded_restore.
        key = {"P-1": "张三"}
        response = {"result": "P-1 and Zhang San"}

        with pytest.raises(ValueError):
            restore_body(response, key, field="result", guard=False, aliases={"P-1": "Zhang San"})

    def test_restore_body_forwards_display_marker(self):
        key = {"P-1": "张三"}
        response = {"result": "P-1ⓕ来了"}

        restored = restore_body(response, key, field="result", guard=False, display_marker="ⓕ")

        assert restored["result"] == "张三来了"


class TestRoundtrip:
    def test_should_roundtrip_full_flow(self):
        body = {"text": "张三电话13812345678，邮箱zhang@test.com"}

        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        assert "13812345678" not in redacted["text"]
        assert "zhang@test.com" not in redacted["text"]

        response = {"result": redacted["text"]}
        restored = restore_body(response, key, field="result", guard=False)

        assert "13812345678" in restored["result"]
        assert "zhang@test.com" in restored["result"]


class TestRestoreBodyGuard:
    """Guard-by-default restore for FastAPI (Pattern B)."""

    def test_should_restore_with_guard_and_valid_nonce(self):
        """guard=True + valid nonce → restores successfully."""
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        anchor = make_anchor(key)
        # Simulate LLM response with nonce echoed
        llm_output = redacted["text"] + f"\n{anchor.nonce}"

        result = restore_body(llm_output, key, anchor=anchor, guard=True)

        assert "13812345678" in result

    def test_should_fail_closed_when_nonce_missing(self):
        """guard=True + missing nonce → fail-closed (originals not leaked)."""
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        anchor = make_anchor(key)
        # Response does NOT contain the nonce
        result = restore_body(redacted["text"], key, anchor=anchor, guard=True)

        assert "13812345678" not in result

    def test_should_fail_closed_on_forged_nonce(self):
        """guard=True + wrong nonce → fail-closed (zero originals leaked)."""
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        anchor = make_anchor(key)
        forged = redacted["text"] + "\nforged-nonce-99999"

        result = restore_body(forged, key, anchor=anchor, guard=True)

        assert "13812345678" not in result

    def test_should_restore_dict_field_with_guard(self):
        """guard=True restores a dict field when nonce is present."""
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        anchor = make_anchor(key)
        response = {"result": redacted["text"] + f"\n{anchor.nonce}"}

        restored = restore_body(response, key, field="result", anchor=anchor, guard=True)

        assert "13812345678" in restored["result"]

    def test_detailed_returns_security_events_on_fail(self):
        """detailed=True surfaces security_events when guard fails."""
        body = {"text": "电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        anchor = make_anchor(key)
        # No nonce — should fail-close
        result, details = restore_body(
            redacted["text"], key, anchor=anchor, guard=True, detailed=True
        )

        assert "13812345678" not in result
        assert "security_events" in details
        assert any(e["reason_code"] == "provenance_failed" for e in details["security_events"])

    def test_prompt_anchor_workflow_end_to_end(self):
        """Full caller workflow: redact_body → make_anchor → prompt_anchor → restore_body."""
        body = {"text": "联系人张三，电话13812345678"}
        redacted, key = redact_body(body, mode="fast", lang="zh", salt=42)

        anchor = make_anchor(key)
        system_prompt = prompt_anchor(key, "zh", anchor=anchor)
        assert anchor.nonce in system_prompt

        # Simulate LLM including nonce in response
        llm_output = f"记录: {redacted['text']}\n{anchor.nonce}"

        result = restore_body(llm_output, key, anchor=anchor, guard=True)

        assert "13812345678" in result
