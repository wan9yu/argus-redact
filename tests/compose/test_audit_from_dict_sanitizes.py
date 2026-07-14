"""Theme B / H5: from_dict must sanitize on load, not just on append().

A hand-crafted or tampered on-disk ledger can carry a free-form ``detail`` on a
security_event. Loading it must never let that PII into memory — the same
_sanitize_event projection that append() applies on write must also apply on
load.
"""

import pytest

from argus_redact.compose.audit import AuditLedger

_TAMPERED_EVENT = {
    "type": "security",
    "reason_code": "provenance_failed",
    "count": 1,
    "detail": "SSN 123-45-6789 of John Smith",
}


def _tampered_dict():
    return {
        "schema_version": 1,
        "entries": [
            {
                "seq": 0,
                "timestamp": "t0",
                "kind": "redact",
                "type_counts": {},
                "security_events": [dict(_TAMPERED_EVENT)],
                "content_digest": None,
                "prev_hash": "",
                "entry_hash": "deadbeef",
            }
        ],
    }


def test_from_dict_strips_detail_from_hand_crafted_event():
    d = _tampered_dict()
    ledger = AuditLedger.from_dict(d)
    event = ledger.entries[0].security_events[0]
    assert "detail" not in event
    assert "SSN 123-45-6789" not in repr(ledger.entries[0].security_events)
    assert "John Smith" not in repr(ledger.entries[0].security_events)


def test_from_dict_sanitize_is_noop_for_honest_roundtrip():
    seq = iter(["t0", "t1"])
    led = AuditLedger(clock=lambda: next(seq))
    led.append(
        "redact",
        type_counts={"person": 1},
        security_events=[
            {"type": "security", "reason_code": "keep_downgraded", "count": 1, "detail": "张三"}
        ],
    )
    d = led.to_dict()
    restored = AuditLedger.from_dict(d)
    assert restored.verify() is True
    assert restored.head_digest == led.head_digest


def test_from_dict_without_hmac_key_on_hmac_ledger_raises_clearly():
    seq = iter(["t0"])
    led = AuditLedger(hmac_key=b"secret", clock=lambda: next(seq))
    led.append("redact", type_counts={"person": 1})
    d = led.to_dict()
    assert d["hmac"] is True
    with pytest.raises(ValueError, match="hmac_key"):
        AuditLedger.from_dict(d)


def test_from_dict_with_hmac_key_verifies():
    seq = iter(["t0"])
    led = AuditLedger(hmac_key=b"secret", clock=lambda: next(seq))
    led.append("redact", type_counts={"person": 1})
    d = led.to_dict()
    restored = AuditLedger.from_dict(d, hmac_key=b"secret")
    assert restored.verify() is True


def test_to_dict_keyless_ledger_marks_hmac_false():
    seq = iter(["t0"])
    led = AuditLedger(clock=lambda: next(seq))
    led.append("redact", type_counts={"person": 1})
    assert led.to_dict()["hmac"] is False
