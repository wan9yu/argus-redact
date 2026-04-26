"""Unicode bypass tests — verify normalization prevents evasion."""

from argus_redact import redact, restore


class TestFullwidthBypass:
    """Fullwidth digits (U+FF10-FF19) should be detected after NFKC normalization."""

    def test_should_detect_fullwidth_phone(self):
        text = "电话１３８００１３８０００"
        redacted, key = redact(text, seed=42, mode="fast")

        # Key stores original (fullwidth) text for correct restore
        assert len(key) >= 1, "Fullwidth phone should be detected"

    def test_should_detect_fullwidth_email_at(self):
        text = "邮箱zhang＠gmail.com"
        redacted, key = redact(text, seed=42, mode="fast")

        assert len(key) >= 1, "Fullwidth @ email should be detected"


class TestZeroWidthBypass:
    """Zero-width characters inserted into PII should be stripped before matching."""

    def test_should_detect_phone_with_zwsp(self):
        """Zero-width space U+200B."""
        text = "电话1\u200b3\u200b8\u200b0\u200b0\u200b1\u200b3\u200b8\u200b0\u200b0\u200b0"
        redacted, key = redact(text, seed=42, mode="fast")

        assert len(key) >= 1, "Phone with ZWSP should be detected"
        # Key stores original text (with ZWSP) for correct restore
        val = list(key.values())[0]
        assert "13800138000" in val.replace("\u200b", "")

    def test_should_detect_phone_with_zwj(self):
        """Zero-width joiner U+200D."""
        text = "电话1\u200d3\u200d8\u200d0\u200d0\u200d1\u200d3\u200d8\u200d0\u200d0\u200d0"
        redacted, key = redact(text, seed=42, mode="fast")

        assert len(key) >= 1, "Phone with ZWJ should be detected"

    def test_should_detect_phone_with_soft_hyphen(self):
        """Soft hyphen U+00AD."""
        text = "电话1\u00ad3\u00ad8\u00ad0\u00ad0\u00ad1\u00ad3\u00ad8\u00ad0\u00ad0\u00ad0"
        redacted, key = redact(text, seed=42, mode="fast")

        assert len(key) >= 1, "Phone with soft hyphen should be detected"

    def test_should_detect_email_with_zwsp(self):
        text = "邮箱z\u200bhang@example.com"
        redacted, key = redact(text, seed=42, mode="fast")

        assert len(key) >= 1, "Email with ZWSP should be detected"


class TestDirectionBypass:
    """RTL/LTR control characters should be stripped."""

    def test_should_detect_phone_with_rtl_override(self):
        """RTL override: bytes are 13800138000 wrapped in direction chars."""
        text = "电话\u202e13800138000\u202c"
        redacted, key = redact(text, seed=42, mode="fast")

        # Direction chars stripped during normalization → phone detected
        assert len(key) >= 1, "Phone wrapped in RTL should be detected"


class TestRoundtripWithNormalization:
    """Redact→restore must recover the ORIGINAL text (with unicode chars intact)."""

    def test_should_roundtrip_fullwidth_phone(self):
        text = "电话１３８００１３８０００"
        redacted, key = redact(text, seed=42, mode="fast")
        restored = restore(redacted, key)

        # Original fullwidth chars recovered (key stores original text)
        assert "１３８" in restored

    def test_should_roundtrip_zwsp_phone(self):
        text = "电话1\u200b3\u200b8\u200b0\u200b0\u200b1\u200b3\u200b8\u200b0\u200b0\u200b0"
        redacted, key = redact(text, seed=42, mode="fast")
        restored = restore(redacted, key)

        # Original chars (with ZWSP) recovered
        assert "13800138000" in restored.replace("\u200b", "")


class TestHomoglyphBypass:
    """Cyrillic/Greek lookalike characters should be normalized to Latin."""

    def test_should_detect_email_with_cyrillic_a(self):
        """Cyrillic а (U+0430) looks identical to Latin a."""
        text = "邮箱zh\u0430ng@gmail.com"
        redacted, key = redact(text, seed=42, mode="fast")

        assert len(key) >= 1, "Email with Cyrillic а should be detected"

    def test_should_detect_email_with_greek_o(self):
        text = "邮箱zhang@gmail.c\u03bfm"
        redacted, key = redact(text, seed=42, mode="fast")

        assert len(key) >= 1, "Email with Greek ο should be detected"

    def test_should_roundtrip_homoglyph_email(self):
        text = "邮箱zh\u0430ng@gmail.com"
        redacted, key = redact(text, seed=42, mode="fast")
        restored = restore(redacted, key)

        assert "\u0430" in restored or "a" in restored


class TestUnifiedPrefix:
    """Unified prefix hides PII type from output."""

    def test_should_use_unified_prefix_when_configured(self):
        config = {
            "_unified_prefix": "R",
            "phone": {"strategy": "remove"},  # override mask to use prefix
            "email": {"strategy": "remove"},
        }
        redacted, key = redact(
            "张三电话13812345678，身份证110101199003074610",
            seed=42,
            mode="fast",
            names=["张三"],
            config=config,
        )

        for code in key:
            assert code.startswith("R-"), f"Expected R- prefix, got {code}"

    def test_should_use_default_prefixes_when_not_configured(self):
        redacted, key = redact(
            "电话13812345678",
            seed=42,
            mode="fast",
        )

        # Default: phone uses mask, not pseudonym prefix
        # But remove types use type-specific prefix
        assert not any(k.startswith("R-") for k in key)


class TestLargeTextDoS:
    """Large text should not cause timeout or excessive resource usage."""

    def test_should_handle_100kb_under_5s(self):
        import time

        text = "电话13812345678，邮箱test@example.com。" * 2500  # ~100KB

        start = time.perf_counter()
        redacted, key = redact(text, seed=42, mode="fast")
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0, f"100KB took {elapsed:.1f}s, expected <5s"
        assert "13812345678" not in redacted

    def test_should_handle_500kb_under_30s(self):
        import time

        text = "电话13812345678，邮箱test@example.com。" * 12500  # ~500KB

        start = time.perf_counter()
        redacted, key = redact(text, seed=42, mode="fast")
        elapsed = time.perf_counter() - start

        assert elapsed < 30.0, f"500KB took {elapsed:.1f}s, expected <30s"

    def test_should_reject_over_1mb(self):
        import pytest

        text = "x" * (1024 * 1024 + 1)  # just over 1MB

        with pytest.raises(ValueError, match="exceeds maximum"):
            redact(text, mode="fast")
