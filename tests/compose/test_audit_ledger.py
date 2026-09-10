"""Theme B: AuditLedger append-only hash chain + tamper detection."""

import dataclasses

from argus_redact.compose.audit import AuditLedger

_CLK = iter(["2026-07-11T00:00:00", "2026-07-11T00:00:01", "2026-07-11T00:00:02"])


def _ledger(**kw):
    seq = iter(["t0", "t1", "t2", "t3"])
    return AuditLedger(clock=lambda: next(seq), **kw)


def test_append_should_chain_the_previous_hash():
    led = _ledger()
    e0 = led.append("redact", type_counts={"person": 1})
    e1 = led.append("restore", type_counts={})
    assert e0.seq == 0 and e1.seq == 1
    assert e0.prev_hash == ""
    assert e1.prev_hash == e0.entry_hash
    assert led.head_digest == e1.entry_hash


def test_verify_should_return_true_when_chain_is_clean():
    led = _ledger()
    led.append("redact", type_counts={"person": 1})
    led.append("restore", type_counts={})
    assert led.verify() is True


def test_verify_should_return_false_when_an_entry_is_tampered():
    led = _ledger()
    led.append("redact", type_counts={"person": 1})
    led.append("restore", type_counts={})
    # mutate a stored entry's type_counts (frozen → rebuild the list slot)
    led._entries[0] = dataclasses.replace(led._entries[0], type_counts={"person": 999})
    assert led.verify() is False


def test_verify_should_return_false_when_an_entry_is_reordered_or_dropped():
    led = _ledger()
    led.append("redact", type_counts={"person": 1})
    led.append("restore", type_counts={})
    led._entries.pop(0)  # drop first → seq/prev_hash chain breaks
    assert led.verify() is False


def test_append_should_sanitize_event_detail():
    led = _ledger()
    e = led.append(
        "redact",
        type_counts={"person": 1},
        security_events=[
            {"type": "security", "reason_code": "keep_downgraded", "count": 1, "detail": "张三"}
        ],
    )

    assert e.security_events == (
        {"type": "security", "reason_code": "keep_downgraded", "count": 1},
    )


def test_hmac_ledger_should_verify_and_differ_from_plain_ledger():
    plain = _ledger()
    keyed = _ledger(hmac_key=b"secret")
    plain.append("redact", type_counts={"person": 1})
    keyed.append("redact", type_counts={"person": 1})
    assert plain.verify() is True and keyed.verify() is True
    assert plain.head_digest != keyed.head_digest
