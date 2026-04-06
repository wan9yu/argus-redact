"""Tests for Chinese digit normalization — integrated into normalize pipeline.

Chinese/formal digit sequences are normalized to ASCII digits in normalize_text(),
so existing regex patterns match them directly. No separate hint/scanner needed.
"""

from argus_redact.pure.normalize import normalize_text


class TestChineseDigitNormalization:
    """normalize_text should convert 7+ Chinese digit sequences to ASCII."""

    def test_should_normalize_chinese_digit_phone(self):
        text = "手机号一三八零零一三八零零零"
        norm, omap = normalize_text(text)

        assert "13800138000" in norm
        assert omap is not None

    def test_should_normalize_mixed_chinese_ascii(self):
        text = "电话一38零零1三8零零0"
        norm, omap = normalize_text(text)

        assert "13800138000" in norm

    def test_should_normalize_formal_chinese_digits(self):
        text = "号码壹叁捌零零壹叁捌零零零"
        norm, omap = normalize_text(text)

        assert "13800138000" in norm

    def test_should_not_normalize_short_sequences(self):
        text = "三月份去了五层楼"
        norm, omap = normalize_text(text)

        assert "三" in norm  # not converted
        assert "五" in norm  # not converted

    def test_should_not_normalize_isolated_digits(self):
        text = "第一名和第二名"
        norm, omap = normalize_text(text)

        assert "一" in norm
        assert "二" in norm

    def test_should_preserve_offset_mapping(self):
        text = "他的手机一三八零零一三八零零零好记"
        norm, omap = normalize_text(text)

        assert "13800138000" in norm
        # Offset map should point back to original positions
        idx = norm.index("1")
        assert omap[idx] == 4  # "一" is at position 4 in original


class TestChineseDigitEndToEnd:
    """Full pipeline: redact() should detect and roundtrip Chinese digit PII."""

    def test_should_detect_chinese_digit_phone(self):
        from argus_redact import redact

        text = "手机号一三八零零一三八零零零"
        redacted, key = redact(text, seed=42, mode="fast")

        assert len(key) >= 1

    def test_should_detect_mixed_digit_phone(self):
        from argus_redact import redact

        text = "电话一38零零1三8零零0"
        redacted, key = redact(text, seed=42, mode="fast")

        assert len(key) >= 1

    def test_should_roundtrip_chinese_digit_phone(self):
        from argus_redact import redact, restore

        text = "手机号一三八零零一三八零零零"
        redacted, key = redact(text, seed=42, mode="fast")
        restored = restore(redacted, key)

        assert "一三八" in restored

    def test_should_not_false_positive_on_natural_text(self):
        from argus_redact import redact

        text = "三月份去了五层楼，买了一个苹果"
        redacted, key = redact(text, seed=42, mode="fast")

        assert key == {}
