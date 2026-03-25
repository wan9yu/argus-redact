"""Tests for structured data redaction — JSON and CSV."""

from argus_redact.structured import redact_csv, redact_json, restore_csv, restore_json


class TestRedactJSON:
    def test_should_redact_flat_dict(self):
        data = {"name": "张三", "phone": "13812345678", "age": 30}

        redacted, key = redact_json(data, mode="fast", seed=42)

        assert "13812345678" not in str(redacted)
        assert redacted["age"] == 30

    def test_should_redact_nested_dict(self):
        data = {
            "user": {"name": "张三", "contact": {"phone": "13812345678"}},
            "action": "login",
        }

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
