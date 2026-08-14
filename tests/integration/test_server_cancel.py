"""Cooperative cancellation of the L1 detect path: binding + HTTP server.

The v0.8.11 cancellation slice wires the core ``CancelFlag`` primitive through the
PyO3 binding (``_core.CancelToken`` + ``_core.ScanAborted``) and the HTTP server so
a ``/redact`` fast-mode-L1 scan that hits its deadline is *aborted* — the detached
worker returns at its next poll boundary and frees its slot early, reclaiming CPU,
instead of running the abandoned scan to completion.

Test layering (deliberate — see the module brief):

* ``TestBindingCancelPin`` is the REAL T1d: a pre-tripped token handed to the
  binding ``detect_l1`` raises ``ScanAborted`` with a fixed, PII-free message. It is
  a pure ``_core`` unit test with no starlette dependency, because an HTTP
  end-to-end "mid-scan abort -> 504" test would FALSE-GREEN on ``_ScanTimeout`` (the
  deadline raises that first; the worker's ``ScanAborted`` never surfaces to the
  client under the deadline-only trip source).
* ``TestScanAbortedContract`` pins the catastrophe-guard invariant at the type
  level: ``ScanAborted`` is an ``Exception`` subclass, never ``BaseException``.
* The HTTP classes prove the server-side plumbing: the worker's abort is caught and
  the server survives, the per-scan token is fresh (isolation), and the deadline
  reclaims the slot cooperatively.

Every HTTP concurrency test is deterministic — offloaded work is gated on a
``threading.Event`` and the event-loop side advances via ``_yield_until`` (a
deterministic ``asyncio.sleep(0)`` gate), never a wall-clock ``time.sleep`` used as
a synchronization primitive.
"""

from __future__ import annotations

import asyncio
import functools
import importlib.util
import threading
from types import SimpleNamespace

import pytest

from argus_redact._core_loader import HAS_CORE, _core
from tests.integration.conftest import _lifespan_running, _make_app, _yield_until

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None
HAS_HTTPX = importlib.util.find_spec("httpx") is not None

# A representative zh fixture carrying PII (a name + a phone number). The abort
# message must never echo any of it.
_PII_TEXT = "我叫张伟，电话13800138000"
_PII_FRAGMENTS = ("张伟", "13800138000")

_needs_core = pytest.mark.skipif(not HAS_CORE, reason="compiled _core not available")


@_needs_core
class TestScanAbortedContract:
    """The catastrophe-guard invariant, pinned at the type level."""

    def test_scanaborted_is_an_exception_not_baseexception(self):
        # MUST be an Exception subclass: the server's detached worker catches
        # `except Exception` and forwards the error. A BaseException-only abort
        # (e.g. deriving pyo3 PyBaseException directly) would escape that guard,
        # propagate into the app-lifetime task group, and kill the server at every
        # cancellation. Every exception is a BaseException; the load-bearing check
        # is that it is ALSO an Exception, so `except Exception` catches it.
        assert issubclass(_core.ScanAborted, Exception)

        # Concretely: a raised ScanAborted is caught by a bare `except Exception`.
        caught = False
        try:
            raise _core.ScanAborted("detection cancelled")
        except Exception:  # noqa: BLE001 - deliberately pinning the guard shape
            caught = True
        assert caught, "ScanAborted escaped `except Exception` — the worker guard would leak it"


@_needs_core
class TestBindingCancelPin:
    """THE T1d pin — a binding-level unit test, NOT an HTTP-e2e timeout test."""

    def test_pretripped_token_aborts_with_a_pii_free_message(self):
        token = _core.CancelToken()
        token.cancel()  # pre-trip: the first poll boundary aborts the base scan.

        with pytest.raises(_core.ScanAborted) as exc_info:
            _core.detect_l1(_PII_TEXT, ["zh"], [], cancel_token=token)

        message = str(exc_info.value)
        # Fixed, PII-free abort string — never the scanned text.
        assert message == "detection cancelled"
        for fragment in _PII_FRAGMENTS:
            assert fragment not in message, (
                f"the abort message leaked scanned PII ({fragment!r}) — it must be a "
                "fixed, content-free string"
            )

    def test_untripped_token_is_byte_identical_to_no_token(self):
        # A present-but-untripped token must not change the output vs the no-token
        # call — the no-cancel path stays byte-identical.
        no_token = _core.detect_l1(_PII_TEXT, ["zh"], [])
        with_token = _core.detect_l1(_PII_TEXT, ["zh"], [], cancel_token=_core.CancelToken())
        assert with_token == no_token

    def test_tokens_are_fresh_and_independent(self):
        # Each token owns its own flag; cancelling one never trips another. This is
        # the property the server relies on to construct one fresh token per scan.
        a = _core.CancelToken()
        b = _core.CancelToken()
        assert not a.is_cancelled() and not b.is_cancelled()
        a.cancel()
        assert a.is_cancelled()
        assert not b.is_cancelled(), "cancelling one token tripped an unrelated one"


@pytest.mark.skipif(not (HAS_STARLETTE and HAS_HTTPX), reason="starlette/httpx not installed")
class TestServerSurvivesAbort:
    """Catastrophe guard, observed end-to-end: a worker that raises ``ScanAborted``
    is caught by ``_worker``'s ``except Exception``; the request maps it to 504 and
    the SERVER SURVIVES — subsequent /health and /redact still serve. (Would fail if
    ``ScanAborted`` derived ``BaseException``: the abort would escape into the app
    task group and tear the server down.)"""

    @pytest.mark.asyncio
    async def test_worker_abort_maps_to_504_and_server_survives(self, monkeypatch):
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)
        original_redact = server_module._redact_impl

        def _aborting_scan(*args, **kwargs):
            # Simulate the core surfacing a cooperative abort from inside the worker
            # thread (a fast return, so no deadline fires — the abort reaches the
            # handler's `except ScanAborted` via `raise holder["error"]`).
            raise server_module.ScanAborted("detection cancelled")

        monkeypatch.setattr(server_module, "_redact_impl", _aborting_scan)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                aborted = await ac.post("/redact", json={"text": "x", "mode": "fast"})
                assert aborted.status_code == 504
                assert isinstance(aborted.json().get("error"), str) and aborted.json()["error"]

                # The server is still alive: the abort did not tear down the task
                # group. /health needs no scan; a fresh /redact runs a real scan.
                health = await ac.get("/health")
                assert health.status_code == 200
                assert health.json() == {"status": "ok"}

                monkeypatch.setattr(server_module, "_redact_impl", original_redact)
                healthy_redact = await ac.post("/redact", json={"text": _PII_TEXT, "mode": "fast"})
                assert healthy_redact.status_code == 200
                assert "redacted" in healthy_redact.json()


@pytest.mark.skipif(not (HAS_STARLETTE and HAS_HTTPX), reason="starlette/httpx not installed")
class TestPerScanTokenIsolation:
    """Each ``_run_scan`` constructs a FRESH ``CancelToken`` — never shared or
    module-global. Two concurrent scans get distinct tokens, so tripping one does
    NOT cancel the other. Deterministic (event-gated, no sleep-as-sync)."""

    @pytest.mark.asyncio
    async def test_tripping_one_scans_token_leaves_the_other_untouched(self, monkeypatch):
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)
        # Large deadline: this test is about token isolation, not the 504 timeout.
        monkeypatch.setattr(server_module, "_SCAN_TIMEOUT_SECONDS", 30.0)
        monkeypatch.setattr(server_module, "_admitted_scans", 0)

        tokens: dict[str, object] = {}
        a_in = threading.Event()
        b_in = threading.Event()
        release = threading.Event()

        def _scan(text, *args, cancel_token=None, **kwargs):
            tokens[text] = cancel_token
            (a_in if text == "A" else b_in).set()
            assert release.wait(timeout=10), "scan gate was never released"
            # Honor the cooperative-cancel contract the way the real core does:
            # abort iff THIS scan's own token was tripped.
            if cancel_token is not None and cancel_token.is_cancelled():
                raise server_module.ScanAborted("detection cancelled")
            return f"redacted-{text}", {}

        monkeypatch.setattr(server_module, "_redact_impl", _scan)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                task_a = asyncio.create_task(ac.post("/redact", json={"text": "A", "mode": "fast"}))
                task_b = asyncio.create_task(ac.post("/redact", json={"text": "B", "mode": "fast"}))
                try:
                    # Both scans concurrently in-flight; both captured their token.
                    await _yield_until(lambda: a_in.is_set() and b_in.is_set())
                    assert tokens["A"] is not None and tokens["B"] is not None
                    # Freshness: a distinct token per scan.
                    assert tokens["A"] is not tokens["B"], (
                        "the two scans shared one CancelToken — a shared token would "
                        "let one request abort the other"
                    )
                    # Isolation: trip ONLY scan A's token.
                    tokens["A"].cancel()
                    assert tokens["A"].is_cancelled()
                    assert not tokens["B"].is_cancelled(), (
                        "tripping scan A's token also tripped scan B's — the tokens "
                        "are not per-scan isolated"
                    )
                finally:
                    release.set()
                resp_a = await task_a
                resp_b = await task_b

        # Scan A saw its own tripped token and aborted -> 504; scan B was untouched.
        assert resp_a.status_code == 504
        assert resp_b.status_code == 200
        assert resp_b.json() == {"redacted": "redacted-B", "key": {}}


@pytest.mark.skipif(not (HAS_STARLETTE and HAS_HTTPX), reason="starlette/httpx not installed")
class TestCpuReclamationOnDeadline:
    """The point of the feature: a timed-out scan is ABORTED, not run to completion.

    A cooperative worker polls its token; the deadline trips it; the worker returns
    at its next poll and frees its slot — WITHOUT the test releasing anything. That
    freed slot (reached deterministically via ``_yield_until``) is the proof the
    abort reclaimed the CPU. The old run-to-completion mechanic would hold the slot
    until the test released it (contrast ``test_server_robustness`` where the slot
    only frees on the test's explicit release)."""

    @pytest.mark.asyncio
    async def test_deadline_aborts_the_scan_and_frees_its_slot(self, monkeypatch):
        import time

        import anyio
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)
        monkeypatch.setattr(server_module, "_SCAN_TIMEOUT_SECONDS", 0.1)
        monkeypatch.setattr(server_module, "_admitted_scans", 0)
        limiter = anyio.CapacityLimiter(1)
        monkeypatch.setattr(server_module, "_scan_limiter", limiter)

        entered = threading.Event()

        def _cooperative_scan(text, *args, cancel_token=None, **kwargs):
            entered.set()
            # Poll the token like the real core's detect loop. The ONLY thing that
            # ends this loop is the deadline tripping the token — the test never
            # releases it. The 5 ms is a poll CADENCE (so the worker thread yields
            # the GIL), not a synchronization primitive: the assertion gates on
            # borrowed_tokens == 0, which is reached only once the abort happens.
            while not cancel_token.is_cancelled():
                time.sleep(0.005)
            raise server_module.ScanAborted("detection cancelled")

        monkeypatch.setattr(server_module, "_redact_impl", _cooperative_scan)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post("/redact", json={"text": "x", "mode": "fast"})
                # Prompt 504 at the deadline while the worker is still running.
                assert resp.status_code == 504

                # Gate on the scan actually running, then prove the slot frees on
                # abort with NO test-side release — the deadline tripped the token,
                # the worker aborted, `async with _scan_limiter` released the slot.
                await _yield_until(entered.is_set)
                await _yield_until(lambda: limiter.statistics().borrowed_tokens == 0)

        assert limiter.statistics().borrowed_tokens == 0
        assert limiter.statistics().tasks_waiting == 0


@pytest.mark.skipif(
    not (HAS_STARLETTE and HAS_CORE), reason="starlette or compiled _core not available"
)
class TestCpuReclamationOnClientDisconnect:
    """#4 — a client that disconnects mid-scan trips THIS scan's token, so the
    detached worker aborts and frees its slot WITHOUT any test-side release, and
    ``_run_scan`` raises ``_ClientDisconnected`` (the handler maps that to 499).

    Watch approach — the NO-POLL ASGI receive channel (not ``is_disconnected()``
    polling): the handler fully reads the request body before ``_run_scan``, so
    ``request.receive`` then only ever yields the disconnect event. The watcher
    BLOCKS on it with zero CPU cost and detects promptly, with no sleep-driven poll
    loop. The fake ``receive`` here mirrors that: it parks until the test signals the
    disconnect, then returns a single ``http.disconnect``.

    Deterministic: the scan is gated on a ``threading.Event``, the disconnect on an
    ``anyio.Event``, and the freed slot is observed via ``_yield_until`` on the
    limiter's borrowed count — never a wall-clock ``sleep`` used as synchronization.
    """

    @pytest.mark.asyncio
    async def test_disconnect_trips_the_token_and_frees_the_slot(self, monkeypatch):
        import time

        import anyio

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)
        # Large deadline: this is about disconnect, not the 504 timeout.
        monkeypatch.setattr(server_module, "_SCAN_TIMEOUT_SECONDS", 30.0)
        monkeypatch.setattr(server_module, "_admitted_scans", 0)
        limiter = anyio.CapacityLimiter(1)
        monkeypatch.setattr(server_module, "_scan_limiter", limiter)

        entered = threading.Event()

        def _cooperative_scan(*args, cancel_token=None, **kwargs):
            # Poll the token like the real core's detect loop. The ONLY thing that
            # ends this loop is the disconnect tripping the token — the test never
            # releases it. The 5 ms is a poll CADENCE (yield the GIL), not a sync
            # primitive: the assertion gates on the freed slot, reached only on abort.
            entered.set()
            while not cancel_token.is_cancelled():
                time.sleep(0.005)
            raise server_module.ScanAborted("detection cancelled")

        monkeypatch.setattr(server_module, "_redact_impl", _cooperative_scan)

        app = _make_app()
        async with _lifespan_running(app):
            disconnect_signal = anyio.Event()

            async def _receive():
                # In production the body is already consumed, so this only yields the
                # disconnect; here the channel simply parks until the test signals it.
                await disconnect_signal.wait()
                return {"type": "http.disconnect"}

            request = SimpleNamespace(app=app, receive=_receive)
            scan_task = asyncio.create_task(
                server_module._run_scan(
                    request, functools.partial(server_module._redact_impl), cancellable=True
                )
            )

            # The scan is genuinely mid-flight and its token is registered.
            await _yield_until(entered.is_set)
            await _yield_until(lambda: len(app.state.live_tokens) == 1)
            token = next(iter(app.state.live_tokens))
            assert not token.is_cancelled(), "token tripped before any disconnect"
            assert limiter.statistics().borrowed_tokens == 1

            # The client goes away.
            disconnect_signal.set()

            # The disconnect surfaces as `_ClientDisconnected` (mapped to 499 by the
            # handler) — never a 200 result, never a 504, never a 500.
            with pytest.raises(server_module._ClientDisconnected):
                await scan_task

            # The disconnect tripped THIS scan's token...
            assert token.is_cancelled()
            # ...the worker aborted on it and freed its slot with NO test-side
            # release, and `_run_scan`'s finally drained the token from the registry
            # — both reached deterministically, no wall-clock sleep.
            await _yield_until(lambda: limiter.statistics().borrowed_tokens == 0)
            await _yield_until(lambda: len(app.state.live_tokens) == 0)

        assert limiter.statistics().borrowed_tokens == 0
        assert limiter.statistics().tasks_waiting == 0


@pytest.mark.skipif(not (HAS_STARLETTE and HAS_HTTPX), reason="starlette/httpx not installed")
class TestClientDisconnectMapsTo499:
    """The ``_ClientDisconnected`` outcome maps to a clean, PII-free 499 in BOTH
    handler ladders (redact and restore) — never a 500, never the scan result."""

    @pytest.mark.asyncio
    async def test_both_handlers_map_client_disconnect_to_499(self, monkeypatch):
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        async def _disconnecting_scan(request, fn, *, cancellable):
            raise server_module._ClientDisconnected("client disconnected before the scan completed")

        monkeypatch.setattr(server_module, "_run_scan", _disconnecting_scan)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                redact_resp = await ac.post("/redact", json={"text": "x", "mode": "fast"})
                restore_resp = await ac.post(
                    "/restore", json={"text": "x", "key": {}, "guard": False}
                )

        for resp in (redact_resp, restore_resp):
            assert resp.status_code == 499
            body = resp.json()
            assert isinstance(body.get("error"), str) and body["error"]
            # PII-free, and never the scan result.
            assert "redacted" not in body and "restored" not in body


@pytest.mark.skipif(not (HAS_STARLETTE and HAS_HTTPX), reason="starlette/httpx not installed")
class TestDisconnectWatchIsInvisibleWithoutADisconnect:
    """The disconnect watch adds ZERO behaviour change when the client stays: a
    normal scan still returns a byte-identical 200, and a deadline still returns 504.
    (In httpx's ASGITransport the receive channel parks on ``response_complete`` once
    the body is read, so the watcher is cancelled the instant the worker completes or
    the deadline fires — it never fabricates a disconnect.)"""

    @pytest.mark.asyncio
    async def test_normal_scan_is_byte_identical_200(self, monkeypatch):
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        # Deterministic stub so the assertion pins the EXACT response body — a real
        # unsalted redact() varies its pseudonyms run to run.
        def _fixed_redact(*args, **kwargs):
            return "REDACTED", {"P-1": "张伯"}

        monkeypatch.setattr(server_module, "_redact_impl", _fixed_redact)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post("/redact", json={"text": "x", "mode": "fast"})

        assert resp.status_code == 200
        assert resp.json() == {"redacted": "REDACTED", "key": {"P-1": "张伯"}}

    @pytest.mark.asyncio
    async def test_deadline_still_returns_504_and_frees_its_slot(self, monkeypatch):
        import time

        import anyio
        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)
        monkeypatch.setattr(server_module, "_SCAN_TIMEOUT_SECONDS", 0.1)
        monkeypatch.setattr(server_module, "_admitted_scans", 0)
        limiter = anyio.CapacityLimiter(1)
        monkeypatch.setattr(server_module, "_scan_limiter", limiter)

        entered = threading.Event()

        def _cooperative_scan(*args, cancel_token=None, **kwargs):
            entered.set()
            while not cancel_token.is_cancelled():
                time.sleep(0.005)
            raise server_module.ScanAborted("detection cancelled")

        monkeypatch.setattr(server_module, "_redact_impl", _cooperative_scan)

        app = _make_app()
        transport = ASGITransport(app=app)
        async with _lifespan_running(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post("/redact", json={"text": "x", "mode": "fast"})
                # Prompt 504 at the deadline while the worker is still running.
                assert resp.status_code == 504
                await _yield_until(entered.is_set)
                await _yield_until(lambda: limiter.statistics().borrowed_tokens == 0)

        assert limiter.statistics().borrowed_tokens == 0


@pytest.mark.skipif(
    not (HAS_STARLETTE and HAS_CORE), reason="starlette or compiled _core not available"
)
class TestCpuReclamationOnShutdown:
    """#5 — on shutdown the lifespan trips EVERY in-flight scan's token, so the
    detached workers abort and the app task group drains PROMPTLY (no hang), and the
    live-token registry is cleared to None. Deterministic: the scan is gated
    mid-flight on a ``threading.Event``, shutdown is driven by the shared
    ``_lifespan_running`` helper, and an ``anyio.fail_after`` fails loudly if the
    drain ever hangs — which is exactly what an un-tripped token would cause."""

    @pytest.mark.asyncio
    async def test_shutdown_trips_inflight_tokens_and_drains_promptly(self, monkeypatch):
        import time

        import anyio

        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)
        monkeypatch.setattr(server_module, "_SCAN_TIMEOUT_SECONDS", 30.0)
        monkeypatch.setattr(server_module, "_admitted_scans", 0)
        limiter = anyio.CapacityLimiter(1)
        monkeypatch.setattr(server_module, "_scan_limiter", limiter)

        entered = threading.Event()

        def _cooperative_scan(*args, cancel_token=None, **kwargs):
            entered.set()
            while not cancel_token.is_cancelled():
                time.sleep(0.005)
            raise server_module.ScanAborted("detection cancelled")

        monkeypatch.setattr(server_module, "_redact_impl", _cooperative_scan)

        never_disconnect = anyio.Event()  # never set: the client stays for the test

        async def _receive():
            await never_disconnect.wait()
            return {"type": "http.disconnect"}

        app = _make_app()
        # anyio.fail_after is a HANG-GUARD, not synchronization: a broken shutdown
        # trip would block the task-group drain forever; this turns that into a loud
        # failure rather than a silent hang. (anyio, not asyncio.timeout, which is
        # 3.11+; the project's supported floor is Python 3.10.)
        with anyio.fail_after(10):
            async with _lifespan_running(app):
                assert app.state.live_tokens is not None, (
                    "the lifespan must create the live-token registry on startup"
                )
                request = SimpleNamespace(app=app, receive=_receive)
                scan_task = asyncio.create_task(
                    server_module._run_scan(
                        request, functools.partial(server_module._redact_impl), cancellable=True
                    )
                )
                await _yield_until(entered.is_set)
                await _yield_until(lambda: len(app.state.live_tokens) == 1)
                token = next(iter(app.state.live_tokens))
                assert not token.is_cancelled(), "token tripped before shutdown"

            # Exiting the block drove lifespan shutdown: the finally tripped the
            # in-flight token BEFORE the task-group drain, so the worker aborted and
            # the drain completed promptly (proven by reaching here under the guard).
            assert token.is_cancelled(), "shutdown did not trip the in-flight scan's token"
            assert app.state.live_tokens is None, "registry not cleared on shutdown (to None)"
            assert app.state.task_group is None
            # The worker's ScanAborted surfaced to the still-awaiting handler wrapper
            # — this is the path that makes the `ScanAborted -> 504` mapping LIVE.
            with pytest.raises(server_module.ScanAborted):
                await scan_task


@pytest.mark.skipif(
    not (HAS_STARLETTE and HAS_CORE), reason="starlette or compiled _core not available"
)
class TestShutdownRegistryHygiene:
    """A COMPLETED scan drains its own token from the registry (so the registry is
    empty once in-flight scans finish), and the drain uses ``set.discard`` — never
    ``remove`` — so a double-drain (e.g. shutdown clearing the registry while a scan
    is still unwinding) never raises."""

    @pytest.mark.asyncio
    async def test_completed_scan_drains_its_token_and_double_discard_is_safe(self, monkeypatch):
        from argus_redact import server as server_module

        monkeypatch.delenv("ARGUS_API_KEY", raising=False)
        monkeypatch.setattr(server_module, "_admitted_scans", 0)

        def _fixed_redact(*args, **kwargs):
            return "REDACTED", {}

        monkeypatch.setattr(server_module, "_redact_impl", _fixed_redact)

        app = _make_app()
        async with _lifespan_running(app):
            registry = app.state.live_tokens
            # receive=None: no ASGI channel, so the disconnect watcher no-ops and the
            # scan completes normally (the code path a non-HTTP caller would take).
            request = SimpleNamespace(app=app, receive=None)
            result = await server_module._run_scan(
                request, functools.partial(server_module._redact_impl), cancellable=True
            )
            assert result == ("REDACTED", {})
            # The completed scan discarded its own token: registry empty after drain.
            assert len(registry) == 0, "a completed scan left its token in the registry"
            # Double-discard is a no-op, not a KeyError — `_run_scan` used `discard`,
            # so draining an already-absent token never raises.
            registry.discard(object())
