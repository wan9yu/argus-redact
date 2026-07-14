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
