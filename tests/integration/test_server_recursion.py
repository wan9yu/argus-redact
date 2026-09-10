"""A deeply-nested JSON request body must 400, not crash the request with an
unhandled 500.

``json.loads`` on a body nested deep enough (e.g. thousands of unmatched
``[``) exhausts the C-accelerated decoder's recursion budget and raises
``RecursionError`` — a ``RuntimeError`` subclass, NOT a ``ValueError``, so the
``except ValueError`` guard in ``_parse_json_object`` never caught it. Both
``/redact`` and ``/restore`` route through that one helper, so both endpoints
share the fix.
"""

from __future__ import annotations

import importlib.util

import pytest

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None

pytestmark = pytest.mark.skipif(not HAS_STARLETTE, reason="starlette not installed")

# Well under MAX_HTTP_BODY_BYTES (10 MiB), but far past Python's default
# 1000-frame recursion limit once the JSON decoder recurses one frame per "[".
_DEEPLY_NESTED = "[" * 100_000


@pytest.fixture(scope="module")
def client():
    from starlette.testclient import TestClient

    from tests.integration.conftest import _make_app

    app = _make_app()

    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("endpoint", ["/redact", "/restore"])
def test_redact_and_restore_should_return_4xx_not_500_when_given_deeply_nested_json(
    client, endpoint
):
    resp = client.post(
        endpoint, content=_DEEPLY_NESTED, headers={"content-type": "application/json"}
    )
    assert resp.status_code < 500, f"{endpoint} -> {resp.status_code} (should be 4xx)"
    assert resp.status_code == 400
    assert "error" in resp.json()
