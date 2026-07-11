"""Theme B Component 1: redact(detailed=True) surfaces security_events."""

from argus_redact import redact


def test_detailed_has_security_events_key():
    _text, _key, details = redact("手机13812345678", lang="zh", mode="fast", detailed=True)
    assert "security_events" in details
    assert details["security_events"] == []


def test_detailed_security_events_carries_keep_downgraded():
    _text, _key, details = redact(
        "卡号4111111111111111",
        lang="zh",
        mode="fast",
        detailed=True,
        config={"bank_card": {"strategy": "keep"}},
    )
    codes = [e["reason_code"] for e in details["security_events"]]
    assert "keep_downgraded" in codes
