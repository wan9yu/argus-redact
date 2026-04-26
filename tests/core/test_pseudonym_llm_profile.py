"""End-to-end tests for redact_pseudonym_llm()."""

from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm
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
