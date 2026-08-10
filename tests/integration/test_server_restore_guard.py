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
        app = create_app(allow_no_auth=True)

    with TestClient(app) as client:
        yield client


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


def test_restore_narrow_scope_withholds_without_splicing(client):
    """An out-of-scope pseudonym must come back verbatim, never half-restored.

    The in-scope 李明 is a strict prefix of the out-of-scope 李明华. If the
    withheld pseudonym is absent from the substitution alternation, 李明华
    matches as 李明 + 华 and 王芳's statement is attributed to 张伟 — a
    corrupted identity the response simultaneously reports as "withheld".
    """
    nonce = "abc123deadbeef00"
    resp = client.post(
        "/restore",
        json={
            "text": f"李明华 reported that 李明 left.\n{nonce}",
            "key": {"李明": "张伟", "李明华": "王芳"},
            "anchor": {"nonce": nonce, "scope": ["李明"]},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["restored"] == "李明华 reported that 张伟 left."
    assert "张伟华" not in data["restored"]
    assert "王芳" not in data["restored"]
    codes = [e["reason_code"] for e in data["security_events"]]
    assert "out_of_scope_pseudonym" in codes
