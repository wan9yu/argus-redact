"""Shared HTTP-server test harness for the integration suites.

The false-green meta-guard for the CI ``integration`` / ``integration-presidio``
jobs — ``pytest_sessionfinish``, which fails the run loudly when a job's declared
integration extras did not actually install instead of letting every gated test
skip to a green — lives in the rootmost ``tests/conftest.py``. It is registered
there (not here) so it applies to any session that opts in via
``ARGUS_REQUIRE_INTEGRATION_EXTRAS``, not only ones that collect this directory.
"""

from __future__ import annotations

import asyncio
import contextlib
import warnings

# --- Shared HTTP-server test harness ---------------------------------------
#
# httpx's ``ASGITransport`` never runs the ASGI lifespan protocol, but the HTTP
# server's scan task group is installed BY that lifespan (see
# ``argus_redact.server.create_app``). These helpers drive the real lifespan
# around a request block so both the ``test_server`` and ``test_server_robustness``
# suites can exercise the production wiring without a live uvicorn. They live here
# (not in one test module) so neither suite has to import the other.


async def _yield_until(predicate, *, max_cycles: int = 1_000_000) -> None:
    """Advance the event loop until ``predicate()`` is true.

    Deterministic gate: ``asyncio.sleep(0)`` only yields control (it does not
    wait a fixed duration), letting an offloaded worker thread reach the state
    the predicate checks. Bounded so a genuine deadlock fails loudly instead of
    hanging.
    """
    for _ in range(max_cycles):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("predicate never became true — offloaded work never reached the state")


@contextlib.asynccontextmanager
async def _lifespan_running(app):
    """Drive the app's ASGI lifespan (startup..shutdown) around a request block.

    ``create_app`` installs the app-lifetime scan task group in a Starlette
    lifespan, but httpx's ``ASGITransport`` never runs the lifespan protocol. So
    we run the real lifespan here exactly as an ASGI server would: this sets
    ``app.state.task_group`` for the requests inside the block AND exercises the
    graceful-shutdown drain (the ``async with`` exit waits for in-flight scans)
    on the way out.
    """
    to_app: asyncio.Queue = asyncio.Queue()
    from_app: asyncio.Queue = asyncio.Queue()

    async def receive():
        return await to_app.get()

    async def send(message):
        await from_app.put(message)

    scope = {"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.0"}}
    task = asyncio.create_task(app(scope, receive, send))
    await to_app.put({"type": "lifespan.startup"})
    msg = await from_app.get()
    assert msg["type"] == "lifespan.startup.complete", msg
    try:
        yield
    finally:
        await to_app.put({"type": "lifespan.shutdown"})
        msg = await from_app.get()
        assert msg["type"] == "lifespan.shutdown.complete", msg
        await task


def _make_app():
    from argus_redact.server import create_app

    with warnings.catch_warnings():
        from argus_redact import SecurityWarning

        warnings.simplefilter("ignore", SecurityWarning)
        return create_app(allow_no_auth=True)
