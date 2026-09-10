"""Theme B Component 1: redact(detailed=True) surfaces security_events."""

from argus_redact import redact


def test_redact_detailed_should_report_no_security_events_when_none_occur():
    _text, _key, details = redact("手机13812345678", lang="zh", mode="fast", detailed=True)
    assert "security_events" in details
    assert details["security_events"] == []


def test_redact_detailed_should_report_keep_downgraded_event_when_keep_strategy_used():
    _text, _key, details = redact(
        "卡号4111111111111111",
        lang="zh",
        mode="fast",
        detailed=True,
        config={"bank_card": {"strategy": "keep"}},
    )
    codes = [e["reason_code"] for e in details["security_events"]]
    assert "keep_downgraded" in codes
