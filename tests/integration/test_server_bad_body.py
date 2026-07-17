"""C4 — HTTP /redact returns 400 (not an unhandled 500) on an empty/malformed body.

``handle_redact`` used to call ``await request.json()`` above its try block,
so a JSONDecodeError (a ValueError) propagated as an unhandled 500 instead of
the 400 the ``except (ValueError, TypeError)`` clause already maps other bad
input to. Fixed by moving the parse inside the try, matching how ``/restore``
already does it.
"""

from __future__ import annotations

import importlib.util

import pytest

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None

pytestmark = pytest.mark.skipif(not HAS_STARLETTE, reason="starlette not installed")


@pytest.fixture(scope="module")
def client():
    import warnings

    from starlette.testclient import TestClient

    from argus_redact import SecurityWarning
    from argus_redact.server import create_app

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        return TestClient(create_app(allow_no_auth=True))


def test_redact_empty_body_returns_400_not_500(client):
    resp = client.post("/redact", content="")
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_redact_malformed_json_body_returns_400_not_500(client):
    resp = client.post("/redact", content="{not valid json")
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_restore_empty_body_still_returns_400(client):
    """Confirms Task 4's /restore fix is intact — same failure mode, other endpoint."""
    resp = client.post("/restore", content="")
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_restore_anchor_str_scope_returns_400_not_200(client):
    """F3 — a str scope (e.g. "P-1" instead of ["P-1"]) used to pass straight
    through frozenset() unrejected, becoming frozenset({'P', '-', '1'}) — a
    garbage anchor that still returned 200 instead of a 400."""
    resp = client.post(
        "/restore",
        json={
            "text": "hello P-1",
            "key": {"P-1": "Alice"},
            "anchor": {"nonce": "abc123deadbeef00", "scope": "P-1"},
        },
    )
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_restore_anchor_non_iterable_scope_returns_400_not_500(client):
    """F3 — scope=123 is not iterable; frozenset(123) used to raise an
    unhandled TypeError (500) instead of a clean 400."""
    resp = client.post(
        "/restore",
        json={
            "text": "hello P-1",
            "key": {"P-1": "Alice"},
            "anchor": {"nonce": "abc123deadbeef00", "scope": 123},
        },
    )
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_restore_anchor_non_str_nonce_returns_400(client):
    """F3 — a non-str nonce must also be rejected with 400, not passed through."""
    resp = client.post(
        "/restore",
        json={
            "text": "hello P-1",
            "key": {"P-1": "Alice"},
            "anchor": {"nonce": 12345, "scope": ["P-1"]},
        },
    )
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_restore_anchor_valid_list_scope_still_200(client):
    """Positive control: a well-formed anchor (list scope, str nonce) that
    round-trips must still return 200 — the new validation must not reject
    valid input."""
    nonce = "abc123deadbeef00"
    resp = client.post(
        "/restore",
        json={
            "text": f"hello P-1\n{nonce}",
            "key": {"P-1": "Alice"},
            "anchor": {"nonce": nonce, "scope": ["P-1"]},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "Alice" in data["restored"]


# --- request body size cap (memory-amplification DoS on /redact and /restore) ---


@pytest.fixture
def small_cap(monkeypatch):
    """Shrink the module's body cap so oversized-body tests run fast without
    actually allocating a multi-megabyte payload."""
    from argus_redact import server

    monkeypatch.setattr(server, "MAX_HTTP_BODY_BYTES", 100)
    return 100


def test_redact_oversized_body_returns_413(client, small_cap):
    text = "x" * (small_cap + 1)
    resp = client.post("/redact", json={"text": text})
    assert resp.status_code == 413
    assert "error" in resp.json()


def test_restore_oversized_body_returns_413(client, small_cap):
    text = "x" * (small_cap + 1)
    resp = client.post("/restore", json={"text": text, "key": {}})
    assert resp.status_code == 413
    assert "error" in resp.json()


def test_redact_body_under_cap_still_200(client, small_cap):
    resp = client.post("/redact", json={"text": "hello"})
    assert resp.status_code == 200


def test_redact_malformed_json_under_cap_still_400(client, small_cap):
    """A small malformed-JSON body must still map to 400, not get swallowed
    by the new size check."""
    resp = client.post("/redact", content="{not valid json")
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_redact_chunked_no_content_length_bounds_memory(small_cap):
    """The size cap must bound memory, not just detect an overage after the
    fact. A chunked request has no Content-Length header, so the only way to
    enforce the cap without buffering the whole body first is to stream it
    and abort as soon as the running count exceeds the cap.

    This drives the raw ASGI app with a ``receive`` callable that counts how
    many bytes it has handed over. Against the old ``await request.body()``
    implementation, ``request.body()`` drains every chunk before the length
    check ever runs, so ``pulled_bytes`` reaches the full payload — this
    assertion fails on that code even though the response is still a
    (post-hoc) 413. Against the streaming fix, the app stops asking for more
    chunks once the running count exceeds the cap, so ``pulled_bytes`` stays
    near the cap.
    """
    import asyncio
    import warnings

    from argus_redact import SecurityWarning, server

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        app = server.create_app(allow_no_auth=True)

    chunk = b"x" * 50
    total_chunks = 1000  # 50_000 bytes total -- far more than the 100-byte cap
    state = {"pulled_bytes": 0, "chunks_sent": 0}

    async def receive():
        if state["chunks_sent"] < total_chunks:
            state["chunks_sent"] += 1
            state["pulled_bytes"] += len(chunk)
            return {"type": "http.request", "body": chunk, "more_body": True}
        return {"type": "http.request", "body": b"", "more_body": False}

    messages = []

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/redact",
        "raw_path": b"/redact",
        "headers": [(b"content-type", b"application/json")],
        "query_string": b"",
        "http_version": "1.1",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 12345),
        "root_path": "",
    }

    asyncio.run(app(scope, receive, send))

    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    assert status == 413

    # The whole point: memory must stay bounded to ~cap + one in-flight
    # chunk, not balloon to the full (never-Content-Length'd) payload.
    assert state["pulled_bytes"] <= small_cap + len(chunk)
