"""Theme B: AuditLedger serialization round-trip + record_* sugar."""

import hashlib

import pytest

from argus_redact.compose.audit import _LEDGER_SCHEMA_VERSION, AuditEntry, AuditLedger


def _ledger():
    seq = iter([f"t{i}" for i in range(10)])
    return AuditLedger(clock=lambda: next(seq))


def test_to_from_dict_roundtrip_preserves_verify_and_head():
    led = _ledger()
    led.append("redact", type_counts={"person": 1})
    led.append("restore", type_counts={})
    d = led.to_dict()
    assert d["schema_version"] == _LEDGER_SCHEMA_VERSION
    restored = AuditLedger.from_dict(d)
    assert restored.verify() is True
    assert restored.head_digest == led.head_digest


def test_from_dict_rejects_bad_schema_version():
    with pytest.raises(ValueError):
        AuditLedger.from_dict({"schema_version": 999, "entries": []})


def test_record_redact_builds_type_counts_and_digest():
    led = _ledger()
    details = {
        "entities": [{"type": "person"}, {"type": "person"}, {"type": "phone"}],
        "stats": {},
        "security_events": [],
    }
    entry = led.record_redact(("REDACTED", {"P-1": "x"}, details))
    assert entry.kind == "redact"
    assert entry.type_counts == {"person": 2, "phone": 1}  # counts detections
    assert entry.content_digest == hashlib.sha256("REDACTED".encode("utf-8")).hexdigest()


def test_record_restore_has_no_type_counts_and_no_auto_digest():
    led = _ledger()
    entry = led.record_restore(("张三 came home", {"security_events": []}))
    assert entry.kind == "restore"
    assert entry.type_counts == {}
    assert entry.content_digest is None  # never auto-digest recovered plaintext


def test_from_dict_defensively_copies_inner_event_dicts():
    d = {
        "seq": 0,
        "timestamp": "t0",
        "kind": "redact",
        "type_counts": {},
        "security_events": [{"type": "security", "reason_code": "x", "count": 1}],
        "content_digest": None,
        "prev_hash": "",
        "entry_hash": "deadbeef",
    }
    entry = AuditEntry.from_dict(d)
    assert entry.security_events[0] is not d["security_events"][0]
