"""HTTP /restore guard-by-default behaviour (v0.8.0).

The endpoint now defaults ``guard=True``: a /restore with no anchor fails closed
and the response ALWAYS carries ``security_events``. A caller reconstructs the
provenance/scope anchor as ``{"nonce": str, "scope": [pseudonym, ...]}`` to enable
the round-trip, or passes ``"guard": false`` for the legacy plain substitution.
"""

from __future__ import annotations

import importlib.util
import warnings

import pytest

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None

pytestmark = pytest.mark.skipif(not HAS_STARLETTE, reason="starlette not installed")


@pytest.fixture(scope="module")
def client():
    from starlette.testclient import TestClient

    from argus_redact import SecurityWarning
    from argus_redact.server import create_app

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        return TestClient(create_app(allow_no_auth=True))


def test_restore_with_anchor_round_trips(client):
    """(c) valid anchor + nonce-carrying text → round-trips, security_events == []."""
    key = {"P-1": "Alice"}
    nonce = "abc123deadbeef00"  # >= 16, a plausible token
    resp = client.post(
        "/restore",
        json={
            "text": f"hello P-1\n{nonce}",
            "key": key,
            "anchor": {"nonce": nonce, "scope": ["P-1"]},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "Alice" in data["restored"]
    assert data["security_events"] == []


def test_restore_without_anchor_fails_closed(client):
    """(c) no anchor → fail closed; security_events names guard_no_anchor, text un-restored."""
    resp = client.post(
        "/restore",
        json={"text": "hello P-1", "key": {"P-1": "Alice"}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "Alice" not in data["restored"]
    codes = [e["reason_code"] for e in data["security_events"]]
    assert "guard_no_anchor" in codes


def test_restore_legacy_guard_false_round_trips(client):
    """A caller opts back into plain substitution with guard=false."""
    resp = client.post(
        "/restore",
        json={"text": "hello P-1", "key": {"P-1": "Alice"}, "guard": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "Alice" in data["restored"]
    assert data["security_events"] == []


def test_restore_strict_no_anchor_returns_400_with_events(client):
    """strict=true + a guard trip → 400 carrying the security events."""
    resp = client.post(
        "/restore",
        json={"text": "hello P-1", "key": {"P-1": "Alice"}, "strict": True},
    )
    assert resp.status_code == 400
    data = resp.json()
    codes = [e["reason_code"] for e in data.get("security_events", [])]
    assert "guard_no_anchor" in codes


def test_restore_empty_body_returns_400_not_500(client):
    """(d) a malformed/empty body is a 400 (JSONDecodeError), never an unhandled 500."""
    resp = client.post("/restore", content="")
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_restore_non_dict_anchor_returns_400(client):
    resp = client.post(
        "/restore",
        json={"text": "hi", "key": {"P-1": "Alice"}, "anchor": "not-a-dict"},
    )
    assert resp.status_code == 400
