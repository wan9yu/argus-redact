"""Tests for structured data redaction — JSON (flat, nested, paths) and CSV."""

import pytest

from argus_redact import SecurityWarning
from argus_redact.structured import redact_csv, redact_json, restore_csv, restore_json

# ══════════════════════════════════════════════════════════════
# JSON — basic
# ══════════════════════════════════════════════════════════════


class TestRedactJSON:
    def test_should_redact_flat_dict(self):
        data = {"name": "张三", "phone": "13812345678", "age": 30}
        redacted, key = redact_json(data, mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert redacted["age"] == 30

    def test_should_redact_nested_dict(self):
        data = {"user": {"name": "张三", "contact": {"phone": "13812345678"}}, "action": "login"}
        redacted, key = redact_json(data, mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert redacted["action"] == "login"

    def test_should_redact_list_of_dicts(self):
        data = [
            {"name": "张三", "phone": "13812345678"},
            {"name": "李四", "phone": "15900001234"},
        ]
        redacted, key = redact_json(data, mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert "15900001234" not in str(redacted)

    def test_should_roundtrip_json(self):
        data = {"text": "电话13812345678，邮箱zhang@test.com"}
        redacted, key = redact_json(data, mode="fast", salt=42)
        restored = restore_json(redacted, key)

        assert "13812345678" in str(restored)
        assert "zhang@test.com" in str(restored)


# ════════════════════════════════════════════════════════════���═
# JSON — with_types
# ══════════════════════════════════════════════════════════════


class TestRedactJsonWithTypes:
    def test_should_return_type_map_when_with_types(self):
        data = {"phone": "手机13812345678"}
        redacted, key, types = redact_json(data, mode="fast", salt=42, with_types=True)

        assert "13812345678" not in str(redacted)
        assert isinstance(types, dict)
        assert any(v == "phone" for v in types.values())

    def test_should_return_2_tuple_when_no_with_types(self):
        data = {"phone": "13812345678"}
        result = redact_json(data, mode="fast", salt=42)

        assert len(result) == 2

    def test_should_aggregate_types_across_fields(self):
        data = {
            "phone": "手机13812345678",
            "id": "身份证110101199003074610",
        }
        redacted, key, types = redact_json(data, mode="fast", salt=42, with_types=True)

        type_values = set(types.values())
        assert "phone" in type_values
        assert "id_number" in type_values

    def test_should_work_with_paths_and_with_types(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "手机13812345678"}],
        }
        redacted, key, types = redact_json(
            data,
            paths=["messages[*].content"],
            mode="fast",
            salt=42,
            with_types=True,
        )

        assert redacted["model"] == "gpt-4o"
        assert any(v == "phone" for v in types.values())


# ══════════════════════════════════════════════════════════════
# JSON — selective paths
# ══════════════════════════════════════════════════════════════


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

        assert result["model"] == "gpt-4o"
        assert result["messages"][0]["role"] == "system"
        assert "13812345678" not in result["messages"][1]["content"]

    def test_should_redact_nested_path(self):
        data = {"user": {"name": "张三", "phone": "13812345678", "id": 123}}
        result, key = redact_json(data, paths=["user.phone"], mode="fast")

        assert result["user"]["name"] == "张三"
        assert "13812345678" not in result["user"]["phone"]
        assert result["user"]["id"] == 123

    def test_should_redact_all_when_no_paths(self):
        data = {"name": "张三", "phone": "13812345678"}
        result, key = redact_json(data, mode="fast")

        assert "13812345678" not in str(result)

    def test_should_handle_wildcard_in_list(self):
        data = {
            "items": [
                {"text": "手机13812345678", "type": "message"},
                {"text": "身份证110101199003074610", "type": "id"},
            ]
        }
        result, key = redact_json(data, paths=["items[*].text"], mode="fast")

        assert result["items"][0]["type"] == "message"
        assert "13812345678" not in result["items"][0]["text"]
        assert "110101199003074610" not in result["items"][1]["text"]

    def test_should_handle_multiple_paths(self):
        data = {
            "sender": "张三",
            "receiver": "李四",
            "content": "手机13812345678",
            "timestamp": "2026-01-01",
        }
        result, key = redact_json(data, paths=["sender", "content"], mode="fast")

        assert result["receiver"] == "李四"
        assert result["timestamp"] == "2026-01-01"
        assert "13812345678" not in result["content"]

    def test_should_restore_paths_redacted_json(self):
        data = {"messages": [{"role": "user", "content": "手机13812345678"}]}
        redacted, key = redact_json(data, paths=["messages[*].content"], mode="fast", salt=42)
        restored = restore_json(redacted, key)

        assert "13812345678" in restored["messages"][0]["content"]

    def test_should_handle_nonexistent_path(self):
        data = {"name": "张三"}
        result, key = redact_json(data, paths=["nonexistent.field"], mode="fast")

        assert result["name"] == "张三"
        assert len(key) == 0

    def test_should_redact_block_form_content_under_scoped_path(self):
        # The Anthropic/OpenAI block form
        # content=[{"type":"text","text":...}] must be redacted when scoping to
        # messages[*].content. The leaf sits at depth 5; an exact-depth gate
        # silently skips it and leaks the PII. Scoping to a path means "this
        # subtree", so every string leaf below it must be redacted.
        data = {
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "张三的手机13812345678"}],
                }
            ]
        }
        result, key = redact_json(data, paths=["messages[*].content"], mode="fast", salt=42)

        leaf = result["messages"][0]["content"][0]["text"]
        assert "13812345678" not in leaf
        assert len(key) >= 1


# ══════════════════════════════════════════════════════════════
# CSV
# ══════════════════════════════════════════════════════════════


class TestRedactCSV:
    def test_should_redact_csv_string(self):
        csv_text = "name,phone\n张三,13812345678\n李四,15900001234"
        redacted, key = redact_csv(csv_text, mode="fast", salt=42)

        assert "13812345678" not in redacted
        assert "15900001234" not in redacted

    def test_should_preserve_headers(self):
        csv_text = "name,phone\n张三,13812345678"
        redacted, key = redact_csv(csv_text, mode="fast", salt=42)

        assert redacted.startswith("name,phone")

    def test_should_roundtrip_csv(self):
        csv_text = "name,phone\n张三,13812345678"
        redacted, key = redact_csv(csv_text, mode="fast", salt=42)
        restored = restore_csv(redacted, key)

        assert "13812345678" in restored

    def test_should_redact_first_row_when_headerless(self):
        # A headerless CSV must not leak its first data
        # row. With has_header=False every row is data and must be redacted.
        csv_text = "张三,13812345678\n李四,15900001234"
        redacted, key = redact_csv(csv_text, has_header=False, mode="fast", salt=42)

        assert "13812345678" not in redacted
        assert "15900001234" not in redacted

    def test_should_warn_when_preserved_header_carries_pii(self):
        # Default has_header=True preserves row 0. If that
        # row actually carries detectable PII the caller likely passed a
        # headerless CSV and is silently leaking it — warn loudly.
        csv_text = "张三,13812345678\n李四,15900001234"
        # match= pins this to the header warning — a high-entropy salt avoids the
        # unrelated low-entropy-salt SecurityWarning masking a vacuous pass.
        with pytest.warns(SecurityWarning, match="header"):
            redact_csv(csv_text, mode="fast", salt=bytes(range(32)))
