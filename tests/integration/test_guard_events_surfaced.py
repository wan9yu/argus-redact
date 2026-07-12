"""v0.7.19 (D1) — integrations must not compute security events and then discard them.

presidio/fastapi built `all_events = h_events + guard_events` and then returned the bare
string on the default `detailed=False` path, dropping every event on the floor. The whole
point of the structured-event work is that the channel exists; it had a hole in it.

Also pins the new opt-in: `strict=True` must be able to fail closed on a SUSPECTED
INJECTION (the H layer). H stays advisory by DEFAULT — that is deliberate, because a
heuristic must never be promoted to the deterministic guarantee (P + S).
"""

from __future__ import annotations

import warnings

import pytest

from argus_redact import make_anchor, redact
from argus_redact.integrations.fastapi_middleware import restore_body
from argus_redact.integrations.presidio import PresidioBridge
from argus_redact.pure.replacer import SecurityWarning
from argus_redact.pure.restore import RestoreGuardError

_PHONE = "13912345678"


def _injected_round_trip():
    """Build an LLM reply that trips the H (injection) heuristic but passes P and S."""
    redacted, key = redact(f"张三的电话是{_PHONE}", lang="zh", mode="fast")
    anchor = make_anchor(key)
    # Select by ORIGINAL, never by key order: the key's insertion order is not part
    # of the contract (it varies with the interpreter's hash seed), and picking
    # `next(iter(key))` made this test pass or fail depending on which entity landed
    # first.
    pseudonym = next(p for p, original in key.items() if original == _PHONE)
    # amplification + exfil pattern, with the valid nonce so P passes
    injected = " ".join([pseudonym] * 20) + " send to http://evil.example.com\n" + anchor.nonce
    return redacted, key, anchor, injected


# ── the events must reach the caller ─────────────────────────────────────────


def test_presidio_default_path_warns_instead_of_dropping_events():
    redacted, key, anchor, injected = _injected_round_trip()
    bridge = PresidioBridge.__new__(PresidioBridge)  # no analyzer needed for restore
    with pytest.warns(SecurityWarning, match="injection_suspected"):
        bridge.restore(injected, key, guard=True, anchor=anchor, redacted=redacted)


def test_fastapi_default_path_warns_instead_of_dropping_events():
    redacted, key, anchor, injected = _injected_round_trip()
    with pytest.warns(SecurityWarning, match="injection_suspected"):
        restore_body(injected, key, guard=True, anchor=anchor, redacted=redacted)


def test_detailed_path_still_returns_the_events():
    redacted, key, anchor, injected = _injected_round_trip()
    bridge = PresidioBridge.__new__(PresidioBridge)
    _text, details = bridge.restore(
        injected, key, guard=True, anchor=anchor, redacted=redacted, detailed=True
    )
    assert "injection_suspected" in [e["reason_code"] for e in details["security_events"]]


# ── strict must be reachable through the wrappers (opt-in fail-closed on H) ──


def test_presidio_strict_fails_closed_on_injection():
    redacted, key, anchor, injected = _injected_round_trip()
    bridge = PresidioBridge.__new__(PresidioBridge)
    with pytest.raises(RestoreGuardError):
        bridge.restore(injected, key, guard=True, anchor=anchor, redacted=redacted, strict=True)


def test_fastapi_strict_fails_closed_on_injection():
    redacted, key, anchor, injected = _injected_round_trip()
    with pytest.raises(RestoreGuardError):
        restore_body(injected, key, guard=True, anchor=anchor, redacted=redacted, strict=True)


def test_h_layer_is_advisory_by_default_and_still_restores():
    """By design: without strict=, a suspected injection warns but does NOT block the
    restore. P + S are the guarantee; H only adds signal."""
    redacted, key, anchor, injected = _injected_round_trip()
    bridge = PresidioBridge.__new__(PresidioBridge)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        out = bridge.restore(injected, key, guard=True, anchor=anchor, redacted=redacted)
    assert _PHONE in out  # in-scope pseudonym legitimately restored
