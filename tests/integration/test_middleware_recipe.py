"""Executable spec for the FastAPI middleware recipe in
``docs/integration-frameworks.md`` (## FastAPI > ### Middleware).

This extracts the code fence VERBATIM and executes it, so a future edit that
breaks the recipe (or lets it drift from what actually runs) fails this test
instead of failing silently for a reader who copy-pastes it.

The doc's recipe imports ``from fastapi import FastAPI, Request, Response``
(the section is "## FastAPI", and its sibling endpoint examples do the same),
but ``fastapi`` is not a dependency of this project anywhere (only
``starlette``, via the ``serve`` extra) and is not installed in this test
environment. Rather than rewrite the doc to a different framework, this test
injects a minimal ``sys.modules["fastapi"]`` shim mapping the three imported
names onto their Starlette equivalents — ``fastapi`` re-exports exactly these
(``FastAPI`` IS a ``Starlette`` subclass; ``Request``/``Response`` ARE
Starlette's) — so the doc's own import line runs completely unmodified. When
``fastapi`` genuinely IS installed, the shim is skipped and the real package
is used instead.

Regression coverage for two bugs the recipe used to have:
  - a non-UTF-8 request body raised an uncaught ``UnicodeDecodeError`` (a 500
    for any caller sending a body this middleware wasn't meant to touch);
  - the redact key was written into the (forwarded) request body itself
    (``data["_redact_key"] = key``), so whatever the request was proxied to
    received the means to reverse the redaction it had just received.
"""

from __future__ import annotations

import contextlib
import importlib.util
import re
import sys
import types
from pathlib import Path

import pytest

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None
# Computed once, before any shim is ever installed, so later per-test checks
# never accidentally see our own shim instead of the real package.
HAS_FASTAPI = importlib.util.find_spec("fastapi") is not None

pytestmark = pytest.mark.skipif(not HAS_STARLETTE, reason="starlette not installed")

_DOC_PATH = Path(__file__).resolve().parents[2] / "docs" / "integration-frameworks.md"


def _extract_middleware_recipe() -> str:
    """Pull the ```python ...``` fence out of the FastAPI > Middleware section."""
    text = _DOC_PATH.read_text(encoding="utf-8")
    after_heading = text.split("## FastAPI", 1)[1].split("### Middleware", 1)[1]
    match = re.search(r"```python\n(.*?)\n```", after_heading, re.DOTALL)
    assert match, "could not find the FastAPI middleware code block in the doc"
    return match.group(1)


@contextlib.contextmanager
def _fastapi_shim_if_missing():
    """Make ``import fastapi`` resolve without adding a real dependency.

    Only engages when ``fastapi`` is not importable (the case in this repo's
    own CI/dev environment). Restores whatever ``sys.modules["fastapi"]``
    held before (or removes the key entirely) in a ``finally``, so this
    test can never leave a shimmed ``fastapi`` behind for another test.
    """
    if HAS_FASTAPI:
        yield
        return

    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import Response

    shim = types.ModuleType("fastapi")
    shim.FastAPI = Starlette
    shim.Request = Request
    shim.Response = Response

    had_prior = "fastapi" in sys.modules
    prior = sys.modules.get("fastapi")
    sys.modules["fastapi"] = shim
    try:
        yield
    finally:
        if had_prior:
            sys.modules["fastapi"] = prior
        else:
            sys.modules.pop("fastapi", None)


@pytest.fixture
def middleware_ns() -> dict:
    """Exec the doc's code block fresh for each test — a shared `app` would
    accumulate one `/echo` route per test (Starlette dispatches to the FIRST
    matching route), so a later test would silently hit an earlier test's
    handler instead of its own."""
    code = _extract_middleware_recipe()
    ns: dict = {"__name__": "docs_middleware_recipe"}
    with _fastapi_shim_if_missing():
        exec(compile(code, str(_DOC_PATH), "exec"), ns)
    assert "app" in ns and "RedactBodyMiddleware" in ns
    return ns


@pytest.fixture
def probe(middleware_ns):
    """(client, received) against the recipe's own app, plus an /echo route the
    recipe doesn't define — the middleware runs unmodified, we're only adding
    somewhere for it to forward to. ``received["body"]`` is the raw bytes the
    downstream handler actually got, so a test can check what was forwarded."""
    from starlette.responses import PlainTextResponse
    from starlette.testclient import TestClient

    app = middleware_ns["app"]
    received: dict = {}

    async def echo(request):
        received["body"] = await request.body()
        return PlainTextResponse(received["body"].decode("utf-8", errors="replace"))

    app.add_route("/echo", echo, methods=["POST"])

    with TestClient(app, raise_server_exceptions=False) as client:
        yield client, received


def test_redacts_request_body_before_forwarding(probe):
    client, received = probe

    resp = client.post("/echo", json={"text": "call me at 13812345678"})

    assert resp.status_code == 200
    assert b"13812345678" not in received["body"]  # redacted before it left this process


def test_key_is_never_forwarded_downstream(probe):
    client, received = probe

    client.post("/echo", json={"text": "call me at 13812345678"})

    # The bug this guards: the key used to be spliced into the SAME body that
    # gets forwarded downstream (``data["_redact_key"] = key``).
    assert b"_redact_key" not in received["body"]


def test_non_json_body_passes_through_unmodified(probe):
    client, received = probe

    resp = client.post("/echo", content=b"plain text, not json")

    assert resp.status_code == 200
    assert received["body"] == b"plain text, not json"
    assert resp.text == "plain text, not json"


def test_non_utf8_request_body_does_not_500(probe):
    client, _received = probe

    resp = client.post(
        "/echo",
        content=b"\xff\xfe\x00\x01\x02",
        headers={"content-type": "application/octet-stream"},
    )

    assert resp.status_code != 500
