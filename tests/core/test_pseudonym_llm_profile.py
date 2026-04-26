"""End-to-end tests for redact_pseudonym_llm()."""

import pytest

from argus_redact.glue.redact_pseudonym_llm import (
    PseudonymPollutionError,
    redact_pseudonym_llm,
)
from argus_redact.pure.restore import restore


class TestThreeOutputBasics:
    def test_should_produce_three_distinct_texts(self):
        text = "请拨打 13912345678 联系王建国"
        result = redact_pseudonym_llm(text)

        assert "[" in result.audit_text or "P-" in result.audit_text or "TEL-" in result.audit_text
        assert "19999" in result.downstream_text
        assert "ⓕ" in result.display_text
        assert result.audit_text != result.downstream_text
        assert result.downstream_text != result.display_text

    def test_should_round_trip_audit_text(self):
        text = "请拨打 13912345678 联系王建国"
        result = redact_pseudonym_llm(text, salt=b"fixed-salt-for-test")
        restored = restore(result.audit_text, result.key)
        assert restored == text

    def test_should_round_trip_downstream_text(self):
        text = "请拨打 13912345678 联系王建国"
        result = redact_pseudonym_llm(text, salt=b"fixed-salt-for-test")
        restored = restore(result.downstream_text, result.key)
        assert restored == text

    def test_should_round_trip_display_text(self):
        text = "请拨打 13912345678 联系王建国"
        result = redact_pseudonym_llm(text, salt=b"fixed-salt-for-test")
        restored = restore(result.display_text, result.key, display_marker="ⓕ")
        assert restored == text


class TestCredentialsBypass:
    def test_credentials_should_be_removed_not_realistic(self):
        text = "API key: sk-TEST1234567890abcdefghij1234567890ABCDEFGHIJ"
        result = redact_pseudonym_llm(text)
        assert "sk-TEST" not in result.downstream_text
        # Credentials use OAI-KEY-NNNNN placeholder, not realistic faking
        assert "OAI" in result.downstream_text


class TestDisplayMarkerConfig:
    def test_should_accept_custom_marker(self):
        text = "联系 王建国"
        result = redact_pseudonym_llm(text, display_marker="*")
        assert "ⓕ" not in result.display_text
        assert "*" in result.display_text

    def test_should_accept_preset_name(self):
        text = "联系 王建国"
        result = redact_pseudonym_llm(text, display_marker="chinese")
        assert "(假)" in result.display_text


class TestEnglishProfile:
    def test_should_round_trip_en_phone_ssn_email(self):
        text = "Call (415) 555-1234, SSN 123-45-6789, email john@company.com"
        result = redact_pseudonym_llm(text, lang="en")
        # Realistic-faked en values present
        assert "(555) 555-01" in result.downstream_text
        assert "999-" in result.downstream_text  # SSN 999 area
        assert "@example." in result.downstream_text  # RFC 2606 email
        # Round-trip restores exact original
        assert restore(result.downstream_text, result.key) == text
        assert restore(result.audit_text, result.key) == text
        assert restore(result.display_text, result.key, display_marker="ⓕ") == text

    def test_should_round_trip_credit_card(self):
        text = "Card: 4111-1111-1111-1111"
        result = redact_pseudonym_llm(text, lang="en")
        assert "999999" in result.downstream_text
        assert restore(result.downstream_text, result.key) == text

    def test_should_round_trip_ip_and_mac(self):
        # IPv4 detection requires keyword context (e.g. "IP:") per lang/shared/patterns.py.
        # MAC has no such requirement — bare format match.
        import re

        from argus_redact.pure.reserved_range_scanner import _RESERVED_RANGE_PATTERNS

        text = "Server IP 10.0.0.5 with MAC aa:bb:cc:dd:ee:ff"
        result = redact_pseudonym_llm(text, lang="en")
        assert re.search(_RESERVED_RANGE_PATTERNS["ipv4_shared"], result.downstream_text)
        assert re.search(_RESERVED_RANGE_PATTERNS["mac_shared"], result.downstream_text)
        assert restore(result.downstream_text, result.key) == text


class TestMixedZhEn:
    def test_should_round_trip_mixed_text(self):
        text = "客户Wang at (415) 555-1234, 邮箱 wang@company.com"
        result = redact_pseudonym_llm(text, lang="auto")
        assert restore(result.downstream_text, result.key) == text


class TestCustomReservedNames:
    """v0.5.3: caller can override canonical fake-name tables to allow real users
    named 张三 / John Doe to be redacted instead of triggering false-positive pollution.
    """

    def test_should_redact_real_user_named_zhang_san_when_zh_canonical_disabled(self):
        # By default, '张三' would trip the pollution scanner (it's in canonical list).
        # Empty tuple disables zh canonical name detection entirely.
        result = redact_pseudonym_llm(
            "客户张三的电话13912345678",
            salt=b"test",
            lang=["zh"],
            mode="fast",
            names=["张三"],  # treat as person via fast-mode names list
            reserved_names={"person_zh": ()},
        )
        # Phone redacted as usual
        assert "13912345678" not in result.downstream_text

    def test_should_keep_en_canonical_when_only_zh_overridden(self):
        # Override zh names but leave en canonical names active.
        # 'John Doe' should still be flagged as polluted output.
        with pytest.raises(PseudonymPollutionError):
            redact_pseudonym_llm(
                "Contact John Doe today.",
                salt=b"test",
                lang=["en"],
                reserved_names={"person_zh": ()},  # zh disabled, en still strict
            )

    def test_should_redact_real_user_named_john_doe_when_en_canonical_disabled(self):
        # Symmetric to the zh case: real user named "John Doe" can be redacted
        # by passing reserved_names={"person_en": ()}.
        result = redact_pseudonym_llm(
            "Customer John Doe phoned today.",
            salt=b"test",
            lang=["en"],
            mode="fast",
            names=["John Doe"],
            reserved_names={"person_en": ()},  # en disabled, real user passes through
        )
        # John Doe is now treated as real PII — replaced in downstream_text
        assert "John Doe" not in result.downstream_text

    def test_should_accept_custom_canonical_list(self):
        # Treat custom names as canonical: '杨过' becomes a canonical fake.
        with pytest.raises(PseudonymPollutionError):
            redact_pseudonym_llm(
                "客户杨过来访",
                salt=b"test",
                lang=["zh"],
                reserved_names={"person_zh": ("杨过", "小龙女")},
            )


class TestPollutionDetectionEnShared:
    def test_should_reject_polluted_en_phone(self):
        """Re-redacting realistic-output en text must raise."""
        with pytest.raises(PseudonymPollutionError):
            redact_pseudonym_llm("Call (555) 555-0142 today", lang="en")

    def test_should_reject_polluted_email(self):
        with pytest.raises(PseudonymPollutionError):
            redact_pseudonym_llm("Send to user42@example.com", lang="en")

    def test_should_reject_polluted_ipv4(self):
        with pytest.raises(PseudonymPollutionError):
            redact_pseudonym_llm("Server 192.0.2.10", lang="en")
