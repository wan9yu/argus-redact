"""Tests for suspicious digit sequence hint — L1 detects, L2 verifies."""

from argus_redact._types import Hint, PatternMatch


class TestSuspiciousDigitProducer:
    """L1 should detect sequences of digit-equivalent characters."""

    def test_should_detect_chinese_digit_phone(self):
        from argus_redact.pure.hints import produce_hints

        # Pre-condition: L1 regex found nothing (Chinese digits don't match \d)
        entities = []
        text = "手机号一三八零零一三八零零零"

        hints = produce_hints(entities, text)

        suspicious = [h for h in hints if h.type == "suspicious_digit_sequence"]
        assert len(suspicious) >= 1
        assert suspicious[0].data["normalized"] == "13800138000"

    def test_should_detect_mixed_chinese_ascii_digits(self):
        from argus_redact.pure.hints import produce_hints

        entities = []
        text = "电话一38零零1三8零零0"

        hints = produce_hints(entities, text)

        suspicious = [h for h in hints if h.type == "suspicious_digit_sequence"]
        assert len(suspicious) >= 1
        assert suspicious[0].data["normalized"] == "13800138000"

    def test_should_detect_formal_chinese_digits(self):
        from argus_redact.pure.hints import produce_hints

        entities = []
        text = "号码壹叁捌零零壹叁捌零零零"

        hints = produce_hints(entities, text)

        suspicious = [h for h in hints if h.type == "suspicious_digit_sequence"]
        assert len(suspicious) >= 1
        assert "13800138000" in suspicious[0].data["normalized"]

    def test_should_detect_digits_with_dot_separators(self):
        from argus_redact.pure.hints import produce_hints

        entities = []
        text = "号码1.3.8.0.0.1.3.8.0.0.0"

        hints = produce_hints(entities, text)

        suspicious = [h for h in hints if h.type == "suspicious_digit_sequence"]
        assert len(suspicious) >= 1
        assert suspicious[0].data["normalized"] == "13800138000"

    def test_should_not_detect_short_sequences(self):
        from argus_redact.pure.hints import produce_hints

        entities = []
        text = "三月份去了五层楼"

        hints = produce_hints(entities, text)

        suspicious = [h for h in hints if h.type == "suspicious_digit_sequence"]
        assert len(suspicious) == 0

    def test_should_not_detect_when_regex_already_matched(self):
        """If L1 regex already found the PII, no need for suspicious hint."""
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="13800138000", type="phone", start=3, end=14),
        ]
        text = "电话13800138000"

        hints = produce_hints(entities, text)

        suspicious = [h for h in hints if h.type == "suspicious_digit_sequence"]
        assert len(suspicious) == 0

    def test_should_include_region_in_hint(self):
        from argus_redact.pure.hints import produce_hints

        entities = []
        text = "他的手机一三八零零一三八零零零好记"

        hints = produce_hints(entities, text)

        suspicious = [h for h in hints if h.type == "suspicious_digit_sequence"]
        assert len(suspicious) >= 1
        start, end = suspicious[0].region
        assert start >= 4  # after "他的手机"
        assert end <= len(text) - 2  # before "好记"


class TestSuspiciousDigitConsumer:
    """L2-level consumer: verify suspicious sequences against PII patterns."""

    def test_should_detect_chinese_digit_phone_via_hint(self):
        """End-to-end: redact() should detect phone written in Chinese digits."""
        from argus_redact import redact

        text = "手机号一三八零零一三八零零零"
        redacted, key = redact(text, seed=42, mode="fast")

        # The phone should be detected via suspicious hint → pattern match
        assert len(key) >= 1

    def test_should_detect_mixed_digit_phone_via_hint(self):
        from argus_redact import redact

        text = "电话一38零零1三8零零0"
        redacted, key = redact(text, seed=42, mode="fast")

        assert len(key) >= 1

    def test_should_roundtrip_chinese_digit_phone(self):
        from argus_redact import redact, restore

        text = "手机号一三八零零一三八零零零"
        redacted, key = redact(text, seed=42, mode="fast")
        restored = restore(redacted, key)

        # Original Chinese digits should be recoverable
        assert "一三八" in restored
