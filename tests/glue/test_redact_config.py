"""Tests for redact() with config parameter."""

import pytest
from argus_redact import redact

from tests.conftest import parametrize_examples


class TestRedactConfig:
    @parametrize_examples("redact_config.json")
    def test_should_apply_config_when_provided(self, example):
        redacted, key = redact(
            example["input"],
            seed=42,
            mode="fast",
            config=example["config"],
        )

        assert example["entity_text"] not in redacted
        replacement = [k for k, v in key.items() if v == example["entity_text"]]
        assert len(replacement) == 1, f"Expected one key for {example['entity_text']}"
        r = replacement[0]

        if "replacement_should_start_with" in example:
            assert r.startswith(example["replacement_should_start_with"]), (
                f"{r!r} should start with {example['replacement_should_start_with']!r}: "
                f"{example['description']}"
            )
        if "replacement_should_contain" in example:
            assert example["replacement_should_contain"] in r, (
                f"{r!r} should contain {example['replacement_should_contain']!r}: "
                f"{example['description']}"
            )


class TestRedactConfigValidation:
    def test_should_raise_when_invalid_strategy(self):
        with pytest.raises(ValueError):
            redact("test", config={"phone": {"strategy": "invalid"}})

    def test_should_accept_none_config(self):
        redacted, key = redact("电话13812345678", seed=42, mode="fast", config=None)

        assert "13812345678" not in redacted

    def test_should_accept_dict_config(self):
        config = {"phone": {"strategy": "remove", "replacement": "[PHONE]"}}

        redacted, key = redact("电话13812345678", seed=42, mode="fast", config=config)

        assert "13812345678" not in redacted
        assert any("[PHONE]" in k for k in key)

    def test_should_roundtrip_with_config(self):
        from argus_redact import restore

        config = {"phone": {"strategy": "remove", "replacement": "[PHONE]"}}
        text = "电话13812345678"

        redacted, key = redact(text, seed=42, mode="fast", config=config)
        restored = restore(redacted, key)

        assert "13812345678" in restored
