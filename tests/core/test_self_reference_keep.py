"""v0.5.7: self_reference defaults to "keep" — preserves the original
pronoun / kinship text in the output, restoring LLM intelligibility.

Companion to test_replacer_keep.py: this exercises the full redact()
pipeline end-to-end (issue #12 root-cause fix).
"""

from argus_redact import redact
from argus_redact.pure.hints import produce_hints
from argus_redact.pure.replacer import DEFAULT_STRATEGIES


class TestDefaultStrategy:
    def test_self_reference_default_is_keep(self):
        assert DEFAULT_STRATEGIES["self_reference"] == "keep"


class TestZhPronounKept:
    def test_pronoun_preserved_when_other_pii_present(self):
        text = "我叫张伟, 电话13800138000"
        redacted, key = redact(text, mode="fast", lang="zh", seed=42)

        # 我 / 我叫 preserved verbatim
        assert "我叫" in redacted, f"pronoun must be preserved, got {redacted!r}"
        # No key entry mapping back to "我"
        assert "我" not in key.values(), "self_reference should not be in key dict"
        # Real PII still redacted
        assert "张伟" not in redacted
        assert "13800138000" not in redacted

    def test_bare_pronoun_no_other_pii_preserved(self):
        # Tier 2 path: bare self_reference, no other PII, no command-mode.
        # With keep strategy, the pronoun is still preserved (always).
        text = "我今天很开心"
        redacted, _ = redact(text, mode="fast", lang="zh", seed=42)
        assert redacted == text, f"casual self-reference unchanged, got {redacted!r}"

    def test_issue_12_self_reference_part(self):
        """Verbatim issue #12 input — pronoun part of the fix."""
        text = "我叫张伟, 手机 13800138000. 请原样复述我的姓名和手机号码"
        redacted, _ = redact(text, mode="fast", lang="zh", seed=42)
        assert "我叫" in redacted, "我 preserved"
        assert "我的" in redacted, "我的 preserved"


class TestEnPronounKept:
    def test_my_kinship_preserved(self):
        text = "My mother lives in Tokyo."
        redacted, _ = redact(text, mode="fast", lang="en", seed=42)
        # "My mother" preserved
        assert "My mother" in redacted, f"kinship phrase must be preserved, got {redacted!r}"


class TestHintsStillFire:
    def test_self_reference_still_emits_tier_hint(self):
        # Even though self_reference text is no longer redacted, the type
        # is still detected upstream — so produce_hints sees it and emits
        # the self_reference_tier hint as before.
        from argus_redact._types import PatternMatch

        entities = [
            PatternMatch(text="我", type="self_reference", start=0, end=1, confidence=1.0, layer=1),
        ]
        hints = produce_hints(entities, "我今天很开心")
        assert any(h.type == "self_reference_tier" for h in hints), (
            "self_reference_tier hint should still fire even with keep strategy"
        )


class TestRestoreRoundTrip:
    def test_round_trip_with_kept_self_reference(self):
        from argus_redact import restore

        text = "我叫张伟, 电话13800138000"
        redacted, key = redact(text, mode="fast", lang="zh", seed=42)
        restored = restore(redacted, key)
        # 我 was never replaced — restore is a no-op for self_reference.
        # Other PII restored from key.
        assert restored == text, f"round-trip mismatch:\norig:    {text!r}\nrestored: {restored!r}"
