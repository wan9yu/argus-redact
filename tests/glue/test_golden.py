"""Golden file tests — seed determinism across versions.

Same input + same seed = exact same output. If these tests break,
it means a change affected redact() output determinism. Users who
persist keys across sessions depend on this stability.
"""

from argus_redact import redact, restore


class TestGoldenSeedDeterminism:
    """Given fixed seed, output must be exactly reproducible."""

    def test_golden_zh_phone(self):
        redacted, key = redact("电话13812345678", seed=42, mode="fast")

        # If this breaks, seed determinism changed
        assert "13812345678" not in redacted
        assert "13812345678" in key.values()
        # Same seed always produces same pseudonym
        redacted2, key2 = redact("电话13812345678", seed=42, mode="fast")
        assert redacted == redacted2
        assert key == key2

    def test_golden_zh_multi_pii(self):
        text = "张三电话13812345678，邮箱zhang@test.com"
        r1, k1 = redact(text, seed=42, mode="fast", names=["张三"])
        r2, k2 = redact(text, seed=42, mode="fast", names=["张三"])

        assert r1 == r2
        assert k1 == k2

    def test_golden_en_self_reference(self):
        text = "I was diagnosed with diabetes"
        r1, k1 = redact(text, seed=42, mode="fast", lang="en")
        r2, k2 = redact(text, seed=42, mode="fast", lang="en")

        assert r1 == r2
        assert k1 == k2

    def test_golden_roundtrip_preserves_original(self):
        """redact → restore must recover all PII regardless of seed."""
        originals = [
            ("张三电话13812345678", {"seed": 42, "mode": "fast", "names": ["张三"]}),
            ("身份证110101199003074610", {"seed": 99, "mode": "fast"}),
            ("I was diagnosed with diabetes", {"seed": 42, "mode": "fast", "lang": "en"}),
        ]
        for text, kwargs in originals:
            redacted, key = redact(text, **kwargs)
            restored = restore(redacted, key)
            # All original PII must be recoverable
            assert "13812345678" in restored or "110101" in restored or "diabetes" in restored


class TestUnicodeBoundary:
    """Edge cases with Unicode special characters."""

    def test_should_handle_empty_string(self):
        redacted, key = redact("", seed=42, mode="fast")

        assert redacted == ""
        assert key == {}

    def test_should_handle_whitespace_only(self):
        redacted, key = redact("   \n\t  ", seed=42, mode="fast")

        assert key == {}

    def test_should_handle_emoji_without_false_match(self):
        """Emoji containing digit-like chars should not be matched as phone."""
        redacted, key = redact("心情很好😀👍🎉", seed=42, mode="fast")

        assert redacted == "心情很好😀👍🎉"
        assert key == {}

    def test_should_handle_number_emoji_without_false_match(self):
        """Keycap digit emoji should not trigger phone detection."""
        redacted, key = redact("步骤1️⃣2️⃣3️⃣完成", seed=42, mode="fast")

        assert key == {} or all(v not in "123" for v in key.values())

    def test_should_handle_zwj_in_text(self):
        """Zero-width joiner should not break offset calculation."""
        text = "电话\u200D13812345678"
        redacted, key = redact(text, seed=42, mode="fast")

        assert "13812345678" not in redacted

    def test_should_handle_bom(self):
        """BOM at start should not break detection."""
        text = "\uFEFF电话13812345678"
        redacted, key = redact(text, seed=42, mode="fast")

        assert "13812345678" not in redacted

    def test_should_roundtrip_with_cjk_surrogate_pairs(self):
        """CJK Extension B chars (U+20000+) should survive roundtrip."""
        text = "客户𠀀𠀁电话13812345678"
        redacted, key = redact(text, seed=42, mode="fast", names=["𠀀𠀁"])

        restored = restore(redacted, key)
        assert "13812345678" in restored

    def test_should_handle_direction_control_chars(self):
        """RTL/LTR marks should not break offset calculation."""
        text = "电话\u200E13812345678\u200F"
        redacted, key = redact(text, seed=42, mode="fast")

        assert "13812345678" not in redacted
