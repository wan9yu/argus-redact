"""Tests for the `remove` strategy with an empty `replacement`.

C2: `config={"type": {"strategy": "remove", "replacement": ""}}` deletes the
value from the redacted output, but MUST NOT register an empty-string key
entry (`"" -> original`). On restore, an empty-string surrogate is a
zero-width match that fires between every character of the text — exploding
and duplicating the original throughout it instead of leaving a clean no-op.
See `replace.rs::ReplaceSession::process` (the per-entity key-commit site).
"""

from argus_redact import redact, restore


class TestRemoveEmptyReplacementNoKeyEntry:
    def test_empty_replacement_removes_both_values_and_registers_no_empty_key(self):
        text = "Call 13812345678 or 13900001111"
        config = {"phone": {"strategy": "remove", "replacement": ""}}
        redacted, key = redact(text, salt=42, mode="fast", lang="en", config=config)

        assert "13812345678" not in redacted
        assert "13900001111" not in redacted
        assert "" not in key, f"empty-string key entry must never be registered: {key!r}"

    def test_restore_after_empty_replacement_is_a_clean_no_op(self):
        text = "Call 13812345678 or 13900001111"
        config = {"phone": {"strategy": "remove", "replacement": ""}}
        redacted, key = redact(text, salt=42, mode="fast", lang="en", config=config)

        restored = restore(redacted, key, guard=False)

        # A clean no-op on the removed spans: the redacted text comes back
        # unchanged, not exploded/duplicated by a zero-width "" surrogate
        # matching between every character.
        assert restored == redacted
        # The original digits must not reappear at all, let alone multiplied
        # throughout the string (the catastrophic pre-fix symptom).
        assert "13812345678" not in restored
        assert "13900001111" not in restored
        assert restored.count("1") <= redacted.count("1")


class TestRemoveNonEmptyReplacementStillRoundTrips:
    """Positive control: a non-empty `remove` replacement is unaffected — it
    still registers its key entry and restores normally."""

    def test_non_empty_replacement_registers_key_and_restores(self):
        text = "电话13812345678"
        config = {"phone": {"strategy": "remove", "replacement": "[PHONE]"}}
        redacted, key = redact(text, salt=42, mode="fast", config=config)

        assert "13812345678" not in redacted
        assert any("[PHONE]" in k for k in key)

        restored = restore(redacted, key, guard=False)
        assert "13812345678" in restored

    def test_default_remove_strategy_pseudonym_code_still_roundtrips(self):
        # No explicit `replacement` configured → falls back to the per-type
        # pseudonym generator path (untouched by this fix).
        text = "电话13812345678"
        config = {"phone": {"strategy": "remove"}}
        redacted, key = redact(text, salt=42, mode="fast", config=config)

        assert "13812345678" not in redacted
        assert "" not in key

        restored = restore(redacted, key, guard=False)
        assert restored == text
