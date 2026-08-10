"""Server robustness: off-loop body parse, honest scan timeout, in-flight bound.

The scan concurrency mechanic is a shielded hybrid: each scan runs in a detached
worker task (owned by an app-lifetime task group installed by ``create_app``'s
lifespan) that holds a ``CapacityLimiter`` slot for the whole lifetime of the
non-preemptible scan thread. The request awaits the worker's completion under a
timeout; on the deadline the client gets a prompt 504 while the worker keeps
running and frees its slot only on completion. The limiter therefore bounds
RUNNING scans, and a timed-out scan never leaks its slot.

Every concurrency test here is deterministic — the offloaded work is gated with
a ``threading.Event`` (or observed via the limiter's own statistics), never a
wall-clock ``time.sleep`` used as a synchronization primitive. The event-loop
side waits for a condition by yielding (``await asyncio.sleep(0)``), so nothing
depends on how fast the machine is.

httpx's ``ASGITransport`` does not run the ASGI lifespan protocol, so the tests
drive it explicitly via ``_lifespan_running`` — this both wires up the app-scoped
scan task group the handlers need and exercises the real graceful-shutdown drain.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import threading
import warnings

import pytest

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None
HAS_HTTPX = importlib.util.find_spec("httpx") is not None

pytestmark = [
    pytest.mark.skipif(not HAS_STARLETTE, reason="starlette not installed"),
    pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed"),
]


async def _yield_until(predicate, *, max_cycles: int = 1_000_000) -> None:
    """Advance the event loop until ``predicate()`` is true.

    Deterministic gate: ``asyncio.sleep(0)`` only yields control (it does not
    wait a fixed duration), letting the offloaded worker thread reach the state
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
    ``server._APP_TASK_GROUP`` for the requests inside the block AND exercises the
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


class TestBodyParseOffLoop:
    """(1) The body reassembly + JSON parse must run OFF the event loop, so a
    large body cannot stall the single loop thread and block GET /health."""

    @pytest.mark.asyncio
    async def test_body_parse_is_dispatched_off_the_event_loop(self, monkeypatch):
        """Structural: the join+parse runs in a worker thread, not the loop thread."""
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        loop_thread = threading.get_ident()
        seen: dict[str, int] = {}
        original = server_module._join_and_parse

        def _spy(chunks):
            seen["thread"] = threading.get_ident()
            return original(chunks)

        monkeypatch.setattr(server_module, "_join_and_parse", _spy)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post("/redact", json={"text": "x", "mode": "fast"})

        assert resp.status_code == 200
        assert "thread" in seen, "the parse path was never invoked"
        assert seen["thread"] != loop_thread, (
            "body parse ran on the event-loop thread — it must be offloaded so a "
            "large body cannot stall the loop"
        )

    @pytest.mark.asyncio
    async def test_health_responds_while_a_body_parse_is_in_flight(self, monkeypatch):
        """Concurrency: GET /health returns while a body parse is blocked."""
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        entered = threading.Event()
        release = threading.Event()
        original = server_module._join_and_parse

        def _blocking_parse(chunks):
            entered.set()
            # Blocks the WORKER thread, not the loop; only ever released by the
            # test, so /health returning is proof the loop stayed free.
            assert release.wait(timeout=10), "parse gate was never released"
            return original(chunks)

        monkeypatch.setattr(server_module, "_join_and_parse", _blocking_parse)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                redact_task = asyncio.create_task(
                    ac.post("/redact", json={"text": "x", "mode": "fast"})
                )
                try:
                    await _yield_until(entered.is_set)
                    health_resp = await ac.get("/health")
                    # Ordering fact (no wall-clock threshold): the parse is still
                    # blocked when /health returns, so the loop was not stalled.
                    parse_still_in_flight = not redact_task.done()
                finally:
                    release.set()
                redact_resp = await redact_task

        assert health_resp.status_code == 200
        assert health_resp.json() == {"status": "ok"}
        assert redact_resp.status_code == 200
        assert parse_still_in_flight, (
            "/health only returned after the blocked body parse finished — the "
            "parse was running inline on the event loop instead of offloaded"
        )


class TestScanTimeout:
    """(2) An honest per-request scan deadline: exceeding it returns 504."""

    @pytest.mark.asyncio
    async def test_redact_scan_exceeding_timeout_returns_504(self, monkeypatch):
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        release = threading.Event()

        def _never_returns(*args, **kwargs):
            # Blocks until the test releases it; the request can therefore ONLY
            # return via the timeout firing — deterministic regardless of speed.
            assert release.wait(timeout=10), "scan gate was never released"
            return "redacted", {}

        monkeypatch.setattr(server_module, "redact", _never_returns)
        monkeypatch.setattr(server_module, "_SCAN_TIMEOUT_SECONDS", 0.1)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                try:
                    resp = await ac.post("/redact", json={"text": "x", "mode": "fast"})
                finally:
                    # Let the abandoned worker unblock so the shutdown drain (and
                    # the slot release) can complete.
                    release.set()

        assert resp.status_code == 504
        body = resp.json()
        assert isinstance(body.get("error"), str) and body["error"], (
            "504 must carry a well-formed contract error body"
        )

    @pytest.mark.asyncio
    async def test_restore_scan_exceeding_timeout_returns_504(self, monkeypatch):
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        release = threading.Event()

        def _never_returns(*args, **kwargs):
            assert release.wait(timeout=10), "scan gate was never released"
            return "restored", {}

        monkeypatch.setattr(server_module, "restore", _never_returns)
        monkeypatch.setattr(server_module, "_SCAN_TIMEOUT_SECONDS", 0.1)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                try:
                    resp = await ac.post("/restore", json={"text": "x", "key": {}, "guard": False})
                finally:
                    release.set()

        assert resp.status_code == 504
        assert isinstance(resp.json().get("error"), str) and resp.json()["error"]


class TestCapacityLimiterBinds:
    """(2) The in-flight bound must actually bind: with the limiter at 1, a
    second concurrent scan queues for a token rather than running immediately."""

    @pytest.mark.asyncio
    async def test_limiter_at_one_makes_the_second_request_queue(self, monkeypatch):
        import anyio
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        lock = threading.Lock()
        entered: list[int] = []
        gate = threading.Event()

        def _gated(*args, **kwargs):
            with lock:
                entered.append(1)
            assert gate.wait(timeout=10), "scan gate was never released"
            return "redacted", {}

        monkeypatch.setattr(server_module, "redact", _gated)
        # A large deadline so the timeout never interferes with this test.
        monkeypatch.setattr(server_module, "_SCAN_TIMEOUT_SECONDS", 30.0)
        # Bound of exactly one in-flight scan.
        limiter = anyio.CapacityLimiter(1)
        monkeypatch.setattr(server_module, "_scan_limiter", limiter)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                t1 = asyncio.create_task(ac.post("/redact", json={"text": "a", "mode": "fast"}))
                t2 = asyncio.create_task(ac.post("/redact", json={"text": "b", "mode": "fast"}))
                try:
                    # The bound binds when the FIRST scan is actually running in
                    # the core (its worker appended to `entered`) while the
                    # limiter holds its one token AND the SECOND worker is queued
                    # for the next — proved from the limiter's own statistics.
                    # Gating on `len(entered) == 1` avoids racing the assertion
                    # against worker-thread startup: the token is acquired
                    # slightly before the worker begins executing the scan.
                    await _yield_until(
                        lambda: (
                            len(entered) == 1
                            and limiter.statistics().borrowed_tokens == 1
                            and limiter.statistics().tasks_waiting == 1
                        )
                    )
                    with lock:
                        # The second request cannot have entered the core: its
                        # worker is blocked on the limiter and never reaches the
                        # offloaded scan.
                        assert entered == [1], (
                            "the second request entered the core scan while the "
                            "limiter was full — the in-flight bound is not binding"
                        )
                finally:
                    gate.set()
                r1 = await t1
                r2 = await t2

        assert r1.status_code == 200
        assert r2.status_code == 200
        with lock:
            assert entered == [1, 1], "both requests should ultimately run once a slot frees"


class TestNoLeakedSlotAfterTimeout:
    """(3) THE KEY INVARIANT — no leaked slot after a timeout.

    A scan that TIMES OUT (client gets 504) still frees its slot when the
    abandoned worker finally completes: the slot is held for the running scan's
    whole lifetime and released EXACTLY ONCE, on completion — never leaked, and
    never freed early on the client's cancelled await. A leaked slot permanently
    loses capacity; this is the invariant the whole shielded-hybrid change exists
    to guarantee. (Would fail under a slot-release-on-cancel mechanic, which frees
    the slot at the deadline while the thread keeps running, and under any leak.)
    """

    @pytest.mark.asyncio
    async def test_timed_out_scan_releases_its_slot_on_completion(self, monkeypatch):
        import anyio
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        entered = threading.Event()  # set on the worker thread once the scan runs
        release = threading.Event()  # the test frees the (already timed-out) scan

        def _slow_scan(*args, **kwargs):
            entered.set()
            assert release.wait(timeout=10), "scan gate was never released"
            return "redacted", {}

        monkeypatch.setattr(server_module, "redact", _slow_scan)
        monkeypatch.setattr(server_module, "_SCAN_TIMEOUT_SECONDS", 0.05)
        limiter = anyio.CapacityLimiter(1)
        monkeypatch.setattr(server_module, "_scan_limiter", limiter)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                try:
                    resp = await ac.post("/redact", json={"text": "x", "mode": "fast"})

                    # The client got a PROMPT 504 while the worker is still running.
                    assert resp.status_code == 504

                    # Gate on the scan actually running in the worker thread: the
                    # token is taken on the loop before the thread starts, so this
                    # proves the worker acquired the slot and is still holding it.
                    await _yield_until(entered.is_set)
                    assert limiter.statistics().borrowed_tokens == 1, (
                        "the timed-out scan must still hold its slot while it runs "
                        "— the deadline is a client response, not a slot release"
                    )

                    # Let the abandoned worker complete. Its `async with
                    # _scan_limiter` MUST release the slot on completion.
                    release.set()
                    await _yield_until(lambda: limiter.statistics().borrowed_tokens == 0)
                finally:
                    release.set()

                assert limiter.statistics().borrowed_tokens == 0, (
                    "the timed-out scan leaked its slot — capacity is permanently "
                    "lost, which is worse than the timeout bug being fixed"
                )
                assert limiter.statistics().tasks_waiting == 0


class TestOverloadShedsHonestly:
    """(4) Under overload — every slot held by a still-running scan — a new
    request is shed with a prompt 504 within the deadline: not a hang, and not an
    unbounded new scan thread."""

    @pytest.mark.asyncio
    async def test_new_request_sheds_with_504_when_all_slots_are_running(self, monkeypatch):
        import anyio
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        lock = threading.Lock()
        entered: list[int] = []
        release = threading.Event()

        def _gated(*args, **kwargs):
            with lock:
                entered.append(1)
            assert release.wait(timeout=10), "scan gate was never released"
            return "redacted", {}

        monkeypatch.setattr(server_module, "redact", _gated)
        monkeypatch.setattr(server_module, "_SCAN_TIMEOUT_SECONDS", 0.1)
        limiter = anyio.CapacityLimiter(1)  # exactly one running scan allowed
        monkeypatch.setattr(server_module, "_scan_limiter", limiter)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                # Occupy the single slot with a still-running (gated) scan.
                first = asyncio.create_task(ac.post("/redact", json={"text": "a", "mode": "fast"}))
                try:
                    await _yield_until(
                        lambda: len(entered) == 1 and limiter.statistics().borrowed_tokens == 1
                    )

                    # A new request cannot get the slot within the deadline -> 504.
                    second = await ac.post("/redact", json={"text": "b", "mode": "fast"})
                    assert second.status_code == 504

                    # Honest load-shed: the shed request never entered the core
                    # (no unbounded new scan thread); only the running scan runs.
                    with lock:
                        assert entered == [1], (
                            "the shed request started a scan anyway — the bound "
                            "did not hold under overload"
                        )
                    assert limiter.statistics().borrowed_tokens == 1
                finally:
                    # Free the running scan; its worker still frees its slot on
                    # completion, then the queued worker for `second` drains too.
                    release.set()
                await _yield_until(lambda: limiter.statistics().borrowed_tokens == 0)
                first_resp = await first

        # `first` shares the small deadline, so it too returned a 504 while its
        # worker kept the slot — the same invariant, observed from the busy side.
        assert first_resp.status_code == 504
        assert limiter.statistics().borrowed_tokens == 0


class TestLifespanWiring:
    """create_app installs a Starlette lifespan that OWNS the scan task group:
    it is created on startup and cleared on shutdown (the graceful-shutdown drain
    point). This is the real production wiring the other tests rely on."""

    @pytest.mark.asyncio
    async def test_lifespan_creates_and_tears_down_the_scan_task_group(self, monkeypatch):
        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        app = _make_app()
        async with _lifespan_running(app):
            assert server_module._APP_TASK_GROUP is not None, (
                "the lifespan must create the app-lifetime scan task group on startup"
            )
        assert server_module._APP_TASK_GROUP is None, (
            "the lifespan must clear the task group on shutdown"
        )
