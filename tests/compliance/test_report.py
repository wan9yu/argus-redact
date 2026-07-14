"""Tests for redact report mode — redact(text, report=True)."""

from argus_redact import redact
from argus_redact._types import RedactReport
from argus_redact.pure.risk import RiskResult


class TestRedactReport:
    def test_should_return_report_when_report_true(self):
        result = redact("手机13812345678", lang="zh", mode="fast", report=True)
        assert isinstance(result, RedactReport)

    def test_report_should_have_redacted_text(self):
        report = redact("手机13812345678", lang="zh", mode="fast", report=True)
        assert "13812345678" not in report.redacted_text

    def test_report_should_have_key(self):
        report = redact("手机13812345678", lang="zh", mode="fast", report=True)
        assert isinstance(report.key, dict)
        assert len(report.key) >= 1

    def test_report_should_have_entities(self):
        report = redact("手机13812345678", lang="zh", mode="fast", report=True)
        assert len(report.entities) >= 1
        entity = report.entities[0]
        assert "type" in entity
        assert "original" in entity

    def test_report_should_have_risk(self):
        report = redact("身份证110101199003074610", lang="zh", mode="fast", report=True)
        assert isinstance(report.risk, RiskResult)
        assert report.risk.level in ("low", "medium", "high", "critical")
        assert report.risk.score > 0

    def test_report_should_have_high_risk_for_id_number(self):
        report = redact("身份证110101199003074610", lang="zh", mode="fast", report=True)
        assert report.risk.level == "critical"
        assert "PIPL Art.51" in report.risk.pipl_articles
        assert "PIPL Art.29" in report.risk.pipl_articles

    def test_report_should_have_stats(self):
        report = redact("手机13812345678", lang="zh", mode="fast", report=True)
        assert "total" in report.stats
        assert report.stats["total"] >= 1

    def test_should_return_tuple_when_report_false(self):
        result = redact("手机13812345678", lang="zh", mode="fast")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_report_no_pii_should_have_zero_risk(self):
        report = redact("今天天气不错", lang="zh", mode="fast", report=True)
        assert report.risk.score == 0.0
        assert report.risk.level == "none"
        assert len(report.entities) == 0

    def test_report_has_residual_personal_data_true_for_pseudonym(self):
        # person entity uses pseudonym strategy by default → residual_personal_data=True
        report = redact("姓名张伟", lang="zh", mode="fast", report=True)
        assert report.residual_personal_data is True

    def test_report_has_residual_personal_data_true_when_all_masked(self):
        # mask writes surrogate->original into report.key (e.g.
        # {'138****5678': '13812345678'}); restore() can recover the
        # original from that key, so the output is still personal data
        # under GDPR Art.4(5) even though mask *looks* irreversible.
        report = redact(
            "手机13812345678",
            lang="zh",
            mode="fast",
            report=True,
            config={"phone": {"strategy": "mask"}},
        )
        assert report.residual_personal_data is True

    def test_report_has_residual_personal_data_true_when_kept(self):
        # keep leaves the original value verbatim in the output — no key
        # needed for it to still be personal data.
        report = redact(
            "call me at 13800138000",
            lang="en",
            mode="fast",
            report=True,
            config={"self_reference": {"strategy": "keep"}, "phone": {"strategy": "keep"}},
        )
        assert report.residual_personal_data is True

    def test_report_has_residual_personal_data_false_when_nothing_detected(self):
        report = redact("今天天气不错", lang="zh", mode="fast", report=True)
        assert len(report.entities) == 0
        assert report.residual_personal_data is False

    def test_report_residual_personal_data_key_actually_reverses_mask(self):
        # Decisive proof: the flag is True *because* the retained key really
        # does reverse the mask output back to the original.
        from argus_redact import restore

        text = "call 13800138000, email bob@acme.com"
        report = redact(
            text,
            lang="en",
            mode="fast",
            report=True,
            config={"phone": {"strategy": "mask"}, "email": {"strategy": "mask"}},
        )
        assert report.residual_personal_data is True
        assert restore(report.redacted_text, report.key, guard=False) == text

    def test_report_security_events_empty_when_no_keep_misconfig(self):
        report = redact("手机13812345678", lang="zh", mode="fast", report=True)
        assert report.security_events == ()

    def test_report_security_events_carries_keep_downgraded(self):
        report = redact(
            "卡号4111111111111111",
            lang="zh",
            mode="fast",
            report=True,
            config={"bank_card": {"strategy": "keep"}},
        )
        codes = [e["reason_code"] for e in report.security_events]
        assert "keep_downgraded" in codes
        # PII-free: no raw card digits anywhere in the events
        assert "4111111111111111" not in str(report.security_events)
