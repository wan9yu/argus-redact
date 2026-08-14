"""Meta-guard for the CI ``integration`` / ``integration-presidio`` jobs.

The server, MCP, and Presidio suites are gated behind ``skipif(not HAS_X)`` /
``pytest.mark.slow`` (see test_server*.py, test_mcp*.py, test_presidio.py) so the
base `test` job's venv (``.[dev]``) never has to carry starlette/mcp/presidio-analyzer.
That gating is exactly how a false green can happen: a CI job installs the extras
and runs this suite, but if the install silently fails (or a packaging change drops
the dependency), every gated test just skips again and pytest still exits 0 — the
job looks green while testing nothing.

The two extras-installing CI jobs set ``ARGUS_REQUIRE_INTEGRATION_EXTRAS`` to a
comma-separated list of the modules they expect to be importable (e.g.
``starlette,mcp`` or ``presidio_analyzer``). When set, this hook fails the run
loudly if any of them are missing. Unset (the default everywhere else — local
dev, the base `test` job), it is a no-op.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import os
import warnings

import pytest

_REQUIRE_ENV = "ARGUS_REQUIRE_INTEGRATION_EXTRAS"


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    required = os.environ.get(_REQUIRE_ENV, "").strip()
    if not required:
        return  # inert unless a CI job explicitly opts in

    missing = [mod for mod in required.split(",") if mod and importlib.util.find_spec(mod) is None]
    if not missing:
        return

    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    message = (
        f"{_REQUIRE_ENV}={required!r} but missing: {', '.join(missing)} — the "
        "gated integration tests would silently skip instead of running. Failing "
        "loudly instead of reporting a false green."
    )
    if reporter is not None:
        reporter.write_line(message, red=True, bold=True)
    session.exitstatus = 1


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
