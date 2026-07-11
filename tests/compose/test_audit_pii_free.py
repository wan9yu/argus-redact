"""Theme B load-bearing invariant: the AuditLedger is PII-free by construction."""

import json

from argus_redact import AuditLedger, redact


def test_ledger_dump_contains_no_originals():
    text = "张三 called 13800138000"
    detailed = redact(text, lang="zh", mode="fast", detailed=True)  # (redacted, key, details)
    led = AuditLedger()
    led.record_redact(detailed)
    dumped = json.dumps(led.to_dict(), ensure_ascii=False)
    for original in ("张三", "13800138000"):
        assert original not in dumped


def test_ledger_strips_pii_from_event_detail():
    led = AuditLedger()
    led.append(
        "redact",
        type_counts={"person": 1},
        security_events=[
            {"type": "security", "reason_code": "keep_downgraded", "count": 1, "detail": "张三"}
        ],
    )
    dumped = json.dumps(led.to_dict(), ensure_ascii=False)
    assert "张三" not in dumped


def test_top_level_exports_importable():
    from argus_redact import AuditEntry, AuditLedger, collect_security_events  # noqa: F401
