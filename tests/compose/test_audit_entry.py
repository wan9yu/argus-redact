"""Theme B: AuditEntry serialization + canonical hashing determinism."""

from argus_redact.compose.audit import (
    AuditEntry,
    _canonical_bytes,
    _digest,
    _sanitize_event,
)


def test_sanitize_event_drops_detail():
    ev = {"type": "security", "reason_code": "keep_downgraded", "count": 1, "detail": "张三"}
    assert _sanitize_event(ev) == {"type": "security", "reason_code": "keep_downgraded", "count": 1}


def test_canonical_bytes_is_deterministic_and_key_order_independent():
    a = _canonical_bytes(0, "t", "redact", {"person": 1, "phone": 2}, [], None, "")
    b = _canonical_bytes(0, "t", "redact", {"phone": 2, "person": 1}, [], None, "")
    assert a == b  # sort_keys makes dict order irrelevant


def test_digest_keyless_vs_hmac_differ():
    b = b"payload"
    assert _digest(b, None) != _digest(b, b"secret")
    assert _digest(b, None) == _digest(b, None)  # stable


def test_entry_roundtrip():
    e = AuditEntry(
        seq=0,
        timestamp="2026-07-11T00:00:00",
        kind="redact",
        type_counts={"person": 1},
        security_events=({"type": "security", "reason_code": "x", "count": 1},),
        content_digest="abc",
        prev_hash="",
        entry_hash="deadbeef",
    )
    d = e.to_dict()
    assert isinstance(d["security_events"], list)  # tuple -> list for JSON
    assert AuditEntry.from_dict(d) == e  # frozen dataclass __eq__; tuple restored
