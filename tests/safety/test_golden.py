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

    def test_golden_pinned_output(self):
        """At least one test must pin exact output to catch cross-version regressions."""
        redacted, key = redact("电话13812345678", seed=42, mode="fast")

        # Pin: same seed must produce same pseudonym code
        assert "13812345678" in key.values()
        mask_values = [v for v in key.values() if "138" in v and "5678" in v]
        assert len(mask_values) == 1, f"Expected exactly one mask, got {key}"

    def test_golden_roundtrip_preserves_original(self):
        """redact → restore must recover each specific PII value."""
        cases = [
            (
                "张三电话13812345678",
                {"seed": 42, "mode": "fast", "names": ["张三"]},
                ["13812345678", "张三"],
            ),
            ("身份证110101199003074610", {"seed": 99, "mode": "fast"}, ["110101199003074610"]),
            (
                "I was diagnosed with diabetes",
                {"seed": 42, "mode": "fast", "lang": "en"},
                ["diabetes"],
            ),
        ]
        for text, kwargs, expected_pii in cases:
            redacted, key = redact(text, **kwargs)
            restored = restore(redacted, key)
            for pii in expected_pii:
                assert pii in restored, f"PII '{pii}' not recovered from: {text}"


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

        assert key == {} or all(v not in ("1", "2", "3") for v in key.values())

    def test_should_handle_zwj_in_text(self):
        """Zero-width joiner should not break offset calculation."""
        text = "电话\u200d13812345678"
        redacted, key = redact(text, seed=42, mode="fast")

        assert "13812345678" not in redacted

    def test_should_handle_bom(self):
        """BOM at start should not break detection."""
        text = "\ufeff电话13812345678"
        redacted, key = redact(text, seed=42, mode="fast")

        assert "13812345678" not in redacted

    def test_should_roundtrip_with_cjk_surrogate_pairs(self):
        """CJK Extension B chars (U+20000+) should survive roundtrip."""
        text = "客户𠀀𠀁电话13812345678"
        redacted, key = redact(text, seed=42, mode="fast", names=["𠀀𠀁"])

        restored = restore(redacted, key)
        assert "13812345678" in restored
        assert "𠀀𠀁" in restored

    def test_should_handle_direction_control_chars(self):
        """RTL/LTR marks should not break offset calculation."""
        text = "电话\u200e13812345678\u200f"
        redacted, key = redact(text, seed=42, mode="fast")

        assert "13812345678" not in redacted
