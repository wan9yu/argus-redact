"""v0.5.7: zh fast-mode person regex no longer over-matches common 3-char
co-occurrences (issue #12 — Argus Gateway demo blocker).

Specifically: when a 3-char candidate's first two chars are already a known
non-name word (e.g. ``任何评`` over ``任何``), the 3-char extension must not
be treated as a person.
"""

from argus_redact import redact


class TestIssue12VerbatimRepro:
    def test_zh_fast_redact_should_preserve_self_reference_while_redacting_only_real_pii(self):
        """Verbatim issue #12 input — only real PII redacted."""
        text = "我叫张伟, 手机 13800138000. 请原样复述我的姓名和手机号码，还有任何评论"
        redacted, key = redact(text, mode="fast", lang="zh", salt=42)

        # self_reference (commit 2)
        assert "我叫" in redacted, "我 must be preserved"
        assert "我的" in redacted, "我的 must be preserved"

        # person false positive (this commit)
        # "任何评" must NOT appear as a redacted entity
        false_positives = [v for v in key.values() if v == "任何评"]
        assert false_positives == [], f"任何评 should not be in key, got {key!r}"
        # "任何评" original text should still be in redacted (not replaced)
        # i.e., the user's "还有任何评论" stays mostly intact
        assert "任何评论" in redacted, f"non-name 3-char must remain unredacted, got {redacted!r}"

        # And real PII still works
        assert "张伟" not in redacted, "张伟 must be redacted"
        assert "13800138000" not in redacted, "phone must be masked"


class TestHighFrequency3CharNotPerson:
    def test_zh_fast_person_detection_should_ignore_common_3char_trigrams(self):
        cases = [
            "任何评论都欢迎",
            "这是个测试用例",
            "还有个问题想问",
        ]

        for text in cases:
            redacted, key = redact(text, mode="fast", lang="zh", salt=42)
            person_keys = [v for v in key.values() if len(v) == 3]
            assert person_keys == [], (
                f"no 3-char co-occurrence should be redacted as person; "
                f"input={text!r} got key={key!r}"
            )


class TestReal3CharNameStillDetected:
    """Recall regression guard: real 3-char names must still match."""

    def test_zh_fast_person_detection_should_detect_3char_names_when_near_pii(self):
        text = "客户张三丰的电话是13912345678"
        redacted, key = redact(text, mode="fast", lang="zh", salt=42)
        # 张三丰 detected with strong evidence (客户 prefix + PII proximity)
        assert "张三丰" not in redacted, f"real 3-char name must be redacted: {redacted!r}"
        assert "张三丰" in key.values()

    def test_zh_fast_redact_should_return_empty_key_when_text_is_pronouns_only(self):
        """Sanity: bare pronoun text should produce empty key (no PII)."""
        text = "我们今天讨论一下"
        _, key = redact(text, mode="fast", lang="zh", salt=42)
        assert key == {}
