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
        app = create_app(allow_no_auth=True)

    with TestClient(app) as client:
        yield client


def test_redact_should_return_400_when_body_is_empty(client):
    resp = client.post("/redact", content="")
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_redact_should_return_400_when_body_is_malformed_json(client):
    resp = client.post("/redact", content="{not valid json")
    assert resp.status_code == 400
    assert "error" in resp.json()


@pytest.mark.parametrize(
    "raw",
    ["[1,2,3]", '"hello"', "42", "null", "true", "3.14", "[]"],
    ids=["array", "string", "int", "null", "bool", "float", "empty-array"],
)
@pytest.mark.parametrize("endpoint", ["/redact", "/restore"])
def test_redact_and_restore_should_return_400_when_json_body_is_not_an_object(
    client, endpoint, raw
):
    """A body that is valid JSON but not an OBJECT used to 500.

    ``json.loads`` succeeds, then ``body.get(...)`` raises ``AttributeError``,
    which sits outside the ``except (ValueError, TypeError)`` net that maps
    every other malformed shape to a clean 400.
    """
    resp = client.post(endpoint, content=raw, headers={"content-type": "application/json"})
    assert resp.status_code == 400, f"{endpoint} {raw!r} -> {resp.status_code}"
    assert "error" in resp.json()


def test_redact_should_name_the_problem_when_body_is_not_an_object(client):
    """The 400 must say what is wrong — 'invalid JSON' would be a lie, the
    body parsed fine."""
    resp = client.post("/redact", content="[1,2,3]", headers={"content-type": "application/json"})
    assert resp.status_code == 400
    assert "object" in resp.json()["error"].lower()


def test_redact_should_return_200_when_body_is_a_valid_object(client):
    """Positive control: the dict check must not reject a valid body."""
    resp = client.post("/redact", json={"text": "hello"})
    assert resp.status_code == 200


def test_restore_should_return_413_when_key_exceeds_max_entries(client):
    """The body cap does not bound the KEY.

    A well-formed 10 MiB body carries on the order of half a million minimal
    key entries, and every one of them is compiled into the restore matcher
    before a byte of ``text`` is scanned. The sharded matcher made that scan
    linear rather than quadratic; linear is not free, and an unauthenticated
    caller choosing the key size still chooses the server's work.
    """
    from argus_redact.server import MAX_RESTORE_KEY_ENTRIES

    over = {f"P-{i}": f"n{i}" for i in range(MAX_RESTORE_KEY_ENTRIES + 1)}
    resp = client.post("/restore", json={"text": "x", "key": over, "guard": False})
    assert resp.status_code == 413, resp.text
    assert "key too large" in resp.json()["error"]


def test_restore_should_return_200_when_key_is_exactly_at_the_cap(client):
    """The cap is a ceiling, not an off-by-one refusal of the last legal key."""
    from argus_redact.server import MAX_RESTORE_KEY_ENTRIES

    at_cap = {f"P-{i}": f"n{i}" for i in range(MAX_RESTORE_KEY_ENTRIES)}
    resp = client.post("/restore", json={"text": "x", "key": at_cap, "guard": False})
    assert resp.status_code == 200, resp.text


def test_redact_should_return_413_when_key_exceeds_max_entries(client):
    """Same cap on /redact, which also accepts a caller-supplied key."""
    from argus_redact.server import MAX_RESTORE_KEY_ENTRIES

    over = {f"P-{i}": f"n{i}" for i in range(MAX_RESTORE_KEY_ENTRIES + 1)}
    resp = client.post("/redact", json={"text": "x", "key": over})
    assert resp.status_code == 413, resp.text
    assert "key too large" in resp.json()["error"]


def test_restore_should_return_400_when_body_is_empty(client):
    """Confirms Task 4's /restore fix is intact — same failure mode, other endpoint."""
    resp = client.post("/restore", content="")
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_restore_should_return_400_when_anchor_scope_is_a_string(client):
    """A str scope (e.g. "P-1" instead of ["P-1"]) used to pass straight
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


def test_restore_should_return_400_when_anchor_scope_is_not_iterable(client):
    """scope=123 is not iterable; frozenset(123) used to raise an
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


def test_restore_should_return_400_when_anchor_nonce_is_not_a_string(client):
    """A non-str nonce must also be rejected with 400, not passed through."""
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


def test_restore_should_return_200_when_anchor_scope_is_a_valid_list(client):
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


# --- /restore must type-check `text` the way /redact already does ---


@pytest.mark.parametrize(
    "text",
    [{"a": 1}, ["a"], 5, 3.5, True, None],
    ids=["dict", "list", "int", "float", "bool", "null"],
)
def test_restore_should_return_400_when_text_is_not_a_string(client, text):
    """The guard's fail-closed no-anchor branch returns before any Rust
    call, so a non-``str`` ``text`` was never type-checked: /restore answered
    200 and echoed the garbage back in ``restored``. /redact 400s on the same
    shape, and so does the ANCHORED /restore branch."""
    resp = client.post("/restore", json={"text": text, "key": {"P-1": "Alice"}})
    assert resp.status_code == 400, f"text={text!r} -> {resp.status_code} {resp.text}"
    assert "error" in resp.json()


def test_restore_should_return_200_when_text_is_a_valid_string(client):
    """Positive control: a valid str text is accepted."""
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
    assert "Alice" in resp.json()["restored"]


# --- request body size cap (memory-amplification DoS on /redact and /restore) ---


@pytest.fixture
def small_cap(monkeypatch):
    """Shrink the module's body cap so oversized-body tests run fast without
    actually allocating a multi-megabyte payload."""
    from argus_redact import server

    monkeypatch.setattr(server, "MAX_HTTP_BODY_BYTES", 100)
    return 100


def test_redact_should_return_413_when_body_exceeds_the_cap(client, small_cap):
    text = "x" * (small_cap + 1)
    resp = client.post("/redact", json={"text": text})
    assert resp.status_code == 413
    assert "error" in resp.json()


def test_restore_should_return_413_when_body_exceeds_the_cap(client, small_cap):
    text = "x" * (small_cap + 1)
    resp = client.post("/restore", json={"text": text, "key": {}})
    assert resp.status_code == 413
    assert "error" in resp.json()


def test_redact_should_return_200_when_body_is_under_the_cap(client, small_cap):
    resp = client.post("/redact", json={"text": "hello"})
    assert resp.status_code == 200


def test_redact_should_return_400_when_body_is_malformed_and_under_the_cap(client, small_cap):
    """A small malformed-JSON body must still map to 400, not get swallowed
    by the new size check."""
    resp = client.post("/redact", content="{not valid json")
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_redact_should_bound_memory_when_chunked_request_lacks_content_length(small_cap):
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
