"""Server robustness: off-loop body parse, honest scan timeout, in-flight bound.

Every concurrency test here is deterministic — the offloaded work is gated with
a ``threading.Event`` (or observed via the limiter's own statistics), never a
wall-clock ``time.sleep`` used as a synchronization primitive. The event-loop
side waits for a condition by yielding (``await asyncio.sleep(0)``), so nothing
depends on how fast the machine is.
"""

from __future__ import annotations

import asyncio
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
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            redact_task = asyncio.create_task(
                ac.post("/redact", json={"text": "x", "mode": "fast"})
            )
            await _yield_until(entered.is_set)
            health_resp = await ac.get("/health")
            # Ordering fact (no wall-clock threshold): the parse is still blocked
            # when /health returns, so the loop was not stalled by it.
            parse_still_in_flight = not redact_task.done()
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
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post("/redact", json={"text": "x", "mode": "fast"})
        finally:
            # Let the abandoned worker thread unblock and exit cleanly.
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
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
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
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            t1 = asyncio.create_task(ac.post("/redact", json={"text": "a", "mode": "fast"}))
            t2 = asyncio.create_task(ac.post("/redact", json={"text": "b", "mode": "fast"}))

            # The bound binds when the FIRST scan is actually running in the core
            # (its worker appended to `entered`) while the limiter holds its one
            # token AND the second request is queued for the next — proved from
            # the limiter's own statistics. Gating on `len(entered) == 1` avoids
            # racing the assertion against worker-thread startup: the token is
            # acquired slightly before the worker begins executing the scan.
            await _yield_until(
                lambda: (
                    len(entered) == 1
                    and limiter.statistics().borrowed_tokens == 1
                    and limiter.statistics().tasks_waiting == 1
                )
            )
            with lock:
                # The second request cannot have entered the core: it is blocked
                # on the limiter and never reaches the offloaded scan.
                assert entered == [1], (
                    "the second request entered the core scan while the limiter "
                    "was full — the in-flight bound is not binding"
                )

            gate.set()
            r1 = await t1
            r2 = await t2

        assert r1.status_code == 200
        assert r2.status_code == 200
        with lock:
            assert entered == [1, 1], "both requests should ultimately run once a slot frees"
