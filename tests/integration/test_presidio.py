"""Tests for Presidio bridge — reversible anonymization on top of Presidio detection."""

import importlib.util

import pytest

HAS_PRESIDIO = importlib.util.find_spec("presidio_analyzer") is not None

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def presidio_bridge():
    if not HAS_PRESIDIO:
        pytest.skip("presidio not installed")
    from argus_redact.integrations.presidio import PresidioBridge

    return PresidioBridge()


class TestPresidioBridge:
    def test_should_redact_person_name(self, presidio_bridge):
        text = "John Smith went to the store"

        redacted, key = presidio_bridge.redact(text, language="en", seed=42)

        assert "John Smith" not in redacted
        assert "John Smith" in key.values()

    def test_should_redact_phone_number(self, presidio_bridge):
        text = "Call me at 555-123-4567"

        redacted, key = presidio_bridge.redact(text, language="en", seed=42)

        assert "555-123-4567" not in redacted

    def test_should_restore_after_redact(self, presidio_bridge):
        text = "John Smith called 555-123-4567"

        redacted, key = presidio_bridge.redact(text, language="en", seed=42)
        restored = presidio_bridge.restore(redacted, key)

        assert "John Smith" in restored

    def test_should_use_per_message_keys(self, presidio_bridge):
        text = "John Smith is here"

        _, key1 = presidio_bridge.redact(text, language="en", seed=42)
        _, key2 = presidio_bridge.redact(text, language="en", seed=99)

        assert key1 != key2

    def test_should_reuse_key_in_batch(self, presidio_bridge):
        _, key = presidio_bridge.redact(
            "John Smith is here",
            language="en",
            seed=42,
        )
        redacted2, key = presidio_bridge.redact(
            "John Smith called Mary",
            language="en",
            seed=42,
            key=key,
        )

        assert "John Smith" not in redacted2
        john_entries = [k for k, v in key.items() if v == "John Smith"]
        assert len(john_entries) == 1

    def test_should_return_empty_key_when_no_pii(self, presidio_bridge):
        text = "The weather is nice today"

        redacted, key = presidio_bridge.redact(text, language="en", seed=42)

        assert redacted == text
        assert key == {}

    def test_should_handle_multiple_entities(self, presidio_bridge):
        text = "John Smith and Mary Jane met at Google"

        redacted, key = presidio_bridge.redact(text, language="en", seed=42)

        assert "John Smith" not in redacted
        assert "Mary Jane" not in redacted
        assert len(key) >= 2


class TestPresidioBridgeRoundtrip:
    def test_should_roundtrip_with_llm_simulation(self, presidio_bridge):
        original = "John Smith, SSN 123-45-6789, works at Google"

        redacted, key = presidio_bridge.redact(
            original,
            language="en",
            seed=42,
        )

        # Simulate LLM processing
        llm_output = f"Summary: {redacted}"

        restored = presidio_bridge.restore(llm_output, key)

        assert "John Smith" in restored
