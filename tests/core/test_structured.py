"""Tests for structured data redaction — JSON (flat, nested, paths) and CSV."""

from argus_redact.structured import redact_csv, redact_json, restore_csv, restore_json


# ══════════════════════════════════════════════════════════════
# JSON — basic
# ══════════════════════════════════════════════════════════════


class TestRedactJSON:
    def test_should_redact_flat_dict(self):
        data = {"name": "张三", "phone": "13812345678", "age": 30}
        redacted, key = redact_json(data, mode="fast", seed=42)

        assert "13812345678" not in str(redacted)
        assert redacted["age"] == 30

    def test_should_redact_nested_dict(self):
        data = {"user": {"name": "张三", "contact": {"phone": "13812345678"}}, "action": "login"}
        redacted, key = redact_json(data, mode="fast", seed=42)

        assert "13812345678" not in str(redacted)
        assert redacted["action"] == "login"

    def test_should_redact_list_of_dicts(self):
        data = [
            {"name": "张三", "phone": "13812345678"},
            {"name": "李四", "phone": "15900001234"},
        ]
        redacted, key = redact_json(data, mode="fast", seed=42)

        assert "13812345678" not in str(redacted)
        assert "15900001234" not in str(redacted)

    def test_should_roundtrip_json(self):
        data = {"text": "电话13812345678，邮箱zhang@test.com"}
        redacted, key = redact_json(data, mode="fast", seed=42)
        restored = restore_json(redacted, key)

        assert "13812345678" in str(restored)
        assert "zhang@test.com" in str(restored)


# ════════════════════════════════════════════════════════════���═
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
        data = {"sender": "张三", "receiver": "李四", "content": "手机13812345678", "timestamp": "2026-01-01"}
        result, key = redact_json(data, paths=["sender", "content"], mode="fast")

        assert result["receiver"] == "李四"
        assert result["timestamp"] == "2026-01-01"
        assert "13812345678" not in result["content"]

    def test_should_restore_paths_redacted_json(self):
        data = {"messages": [{"role": "user", "content": "手机13812345678"}]}
        redacted, key = redact_json(data, paths=["messages[*].content"], mode="fast", seed=42)
        restored = restore_json(redacted, key)

        assert "13812345678" in restored["messages"][0]["content"]

    def test_should_handle_nonexistent_path(self):
        data = {"name": "张三"}
        result, key = redact_json(data, paths=["nonexistent.field"], mode="fast")

        assert result["name"] == "张三"
        assert len(key) == 0


# ══════════════════════════════════════════════════════════════
# CSV
# ══════════════════════════════════════════════════════════════


class TestRedactCSV:
    def test_should_redact_csv_string(self):
        csv_text = "name,phone\n张三,13812345678\n李四,15900001234"
        redacted, key = redact_csv(csv_text, mode="fast", seed=42)

        assert "13812345678" not in redacted
        assert "15900001234" not in redacted

    def test_should_preserve_headers(self):
        csv_text = "name,phone\n张三,13812345678"
        redacted, key = redact_csv(csv_text, mode="fast", seed=42)

        assert redacted.startswith("name,phone")

    def test_should_roundtrip_csv(self):
        csv_text = "name,phone\n张三,13812345678"
        redacted, key = redact_csv(csv_text, mode="fast", seed=42)
        restored = restore_csv(redacted, key)

        assert "13812345678" in restored
