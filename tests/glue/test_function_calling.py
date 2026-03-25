"""Tests for function calling compatibility — redacted text should preserve
semantic structure needed for LLM tool use / function calling."""

import json

from argus_redact import redact, restore

from tests.conftest import parametrize_examples


class TestFunctionCallingCompatibility:
    """Redacted text must preserve enough semantics for LLM function calling."""

    @parametrize_examples("function_calling.json")
    def test_should_preserve_semantic_tokens_when_redacted(self, example):
        lang = example.get("lang", "zh")

        redacted, key = redact(example["input"], seed=42, mode="fast", lang=lang)

        # PII should be gone
        for pii in example["pii_values"]:
            assert (
                pii not in redacted
            ), f"PII '{pii}' still in redacted text: {example['description']}"

        # Semantic tokens (actions, times, amounts) must survive
        for token in example["semantic_tokens"]:
            assert token in redacted, (
                f"Semantic token '{token}' lost in redaction: {example['description']}\n"
                f"Redacted: {redacted}"
            )

    @parametrize_examples("function_calling.json")
    def test_should_roundtrip_when_function_calling(self, example):
        lang = example.get("lang", "zh")

        redacted, key = redact(example["input"], seed=42, mode="fast", lang=lang)
        restored = restore(redacted, key)

        for pii in example["pii_values"]:
            assert pii in restored, f"PII '{pii}' not recovered: {example['description']}"


class TestJsonSchemaCompatibility:
    """Redacted text should be embeddable in JSON without breaking structure."""

    def test_should_produce_json_safe_redacted_text(self):
        text = '张三说："我的电话是13812345678"'

        redacted, key = redact(text, seed=42, mode="fast")

        # Must be valid inside a JSON string
        payload = json.dumps({"content": redacted})
        parsed = json.loads(payload)
        assert parsed["content"] == redacted

    def test_should_produce_valid_json_key(self):
        _, key = redact("电话13812345678，邮箱test@example.com", seed=42, mode="fast")

        # Key must be JSON-serializable
        serialized = json.dumps(key, ensure_ascii=False)
        deserialized = json.loads(serialized)
        assert deserialized == key

    def test_should_work_in_openai_function_call_format(self):
        text = "帮张三订明天下午3点的会议室，电话13812345678"

        redacted, key = redact(text, seed=42, mode="fast")

        # Simulate OpenAI function call message
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": redacted},
        ]
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "book_meeting_room",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "time": {"type": "string"},
                            "contact": {"type": "string"},
                        },
                    },
                },
            }
        ]

        # Must survive JSON roundtrip (regardless of ensure_ascii setting)
        data = {"messages": messages, "tools": tools}
        roundtripped = json.loads(json.dumps(data))
        content = roundtripped["messages"][1]["content"]
        assert content == redacted
        assert "13812345678" not in content

    def test_should_not_break_pseudonym_in_json_value(self):
        text = "Call John at (555) 123-4567"

        redacted, key = redact(text, seed=42, mode="fast", lang="en")

        # Pseudonym/mask as JSON value
        for replacement in key.keys():
            payload = json.dumps({"value": replacement})
            parsed = json.loads(payload)
            assert parsed["value"] == replacement
