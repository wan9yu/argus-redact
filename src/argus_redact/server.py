"""HTTP API server — argus-redact serve.

Usage:
    argus-redact serve                    # default port 8000
    argus-redact serve --port 9000        # custom port
    python -m argus_redact.server         # direct run

Endpoints:
    POST /redact   — redact PII from text
    POST /restore  — restore redacted text with key
    GET  /info     — show version and capabilities
    GET  /health   — health check
"""

from __future__ import annotations

import contextlib
import functools
import importlib
import importlib.util
import json
import os
import secrets
import warnings
from typing import TYPE_CHECKING, Any

from argus_redact import __version__, restore
from argus_redact._core_loader import _core
from argus_redact.exceptions import SecurityWarning
from argus_redact.glue.redact import _redact_impl
from argus_redact.pure.restore import RestoreGuardError
from argus_redact.pure.wire import common_report_fields, risk_payload

# ScanAborted is the cooperative-cancellation abort raised by the Rust L1 detect
# path when a CancelToken is tripped mid-scan (see `_run_scan`). It is a PyException
# subclass — NOT BaseException — so the detached `_worker`'s `except Exception`
# catches it, forwards it, and the server SURVIVES; a BaseException-derived abort
# would escape into the app-lifetime task group and kill the server at every
# cancellation. Mapped to 504 in both handlers, and now LIVE via the server-shutdown
# path: `_lifespan` trips every in-flight scan's token on shutdown, so a handler
# still awaiting `done` wakes on the worker's forwarded ScanAborted → 504. (The
# deadline path raises _ScanTimeout → 504 before the worker's abort can surface, and
# the client-disconnect path raises _ClientDisconnected → 499 without ever reading
# the holder — so neither of those routes a ScanAborted through here.) Sourced from
# the compiled _core; a private never-raised placeholder keeps the except ladders
# well-formed if the mandatory core is somehow absent.
if _core is not None:
    ScanAborted = _core.ScanAborted
else:  # pragma: no cover - the compiled _core is mandatory for the server

    class ScanAborted(Exception):
        """Placeholder used only when the compiled _core is unavailable."""


try:
    import anyio
    from anyio import to_thread
    from starlette.concurrency import run_in_threadpool
    from starlette.requests import Request
    from starlette.responses import JSONResponse
except ImportError:
    if TYPE_CHECKING:
        import anyio
        from anyio import to_thread
        from starlette.concurrency import run_in_threadpool
        from starlette.requests import Request
        from starlette.responses import JSONResponse

# Configurable server-side body cap — a DoS guard against memory amplification
# from unbounded request bodies buffered before any size check.
MAX_HTTP_BODY_BYTES = 10 * 1024 * 1024

# Server-side cap on the number of entries in a `key` — gates both `/restore`
# `key` and `/redact` `key` (the pre-seeded existing-key map).
#
# The body cap alone does not bound this: a 10 MiB body of minimal
# `{"a1":"b",...}` pairs carries on the order of half a million entries, and
# every one of them is compiled into the restore matcher before a single byte
# of `text` is scanned. The sharded matcher made that scan LINEAR in the key
# rather than quadratic — linear is not the same as free, and an unauthenticated
# caller choosing the key size is still choosing the server's work. The cap is
# what turns "expensive" into "bounded"; the matcher only sets the constant.
#
# 10_000 is far above any realistic single-document key (a dense page of PII
# yields tens of entries) while keeping worst-case setup in the millisecond
# range.
MAX_RESTORE_KEY_ENTRIES = 10_000

# In-flight scan concurrency bound + honest per-request scan deadline.
#
# The limiter bounds concurrently RUNNING scans — a real resource bound on the
# number of scan threads alive at once. The timeout is only a client-response
# deadline: a scan that overruns it returns a prompt 504 to the client, but
# because the scan runs on a non-preemptible thread the deadline does NOT reclaim
# the CPU mid-scan. Its slot stays held until the scan actually finishes, so
# under overload the server sheds load via 504s while the thread count stays
# bounded. See `_run_scan` for the full mechanic.
#
# OPERATIONAL ASSUMPTION — the bound below is PER-PROCESS / single-node. Each
# server process enforces only its OWN in-flight limit; a multi-node deployment
# behind a load balancer must ALSO bound concurrency at the gateway (this is not
# a distributed limiter). `uvicorn.run(..., limit_concurrency=...)` is a separate
# connection-level lever at the launch site and is not a substitute for this.
#
# Both are env-overridable so an operator can tune them without a code change.
_MAX_INFLIGHT_SCANS = int(os.environ.get("ARGUS_MAX_INFLIGHT_SCANS", "8"))
_SCAN_TIMEOUT_SECONDS = float(os.environ.get("ARGUS_SCAN_TIMEOUT_SECONDS", "30"))

# Admission ceiling on TOTAL in-flight scans (running + queued) — a
# memory-amplification backpressure bound. `_scan_limiter` above caps concurrent
# EXECUTION, but a detached worker retains its request body (≤ MAX_HTTP_BODY_BYTES,
# 10 MiB) and its key (≤ MAX_RESTORE_KEY_ENTRIES) from the moment it is spawned
# until it finishes — INCLUDING the whole time it sits queued for a limiter slot.
# Without a ceiling on the queue, a request flood retains unbounded memory even
# though only `_MAX_INFLIGHT_SCANS` scans run at once. A request that would push
# the total over this ceiling is shed with a prompt 503 BEFORE its worker is
# spawned, so it never retains its body past the request. Per-process /
# single-node like the limiter; env-tunable; defaults to 2× the in-flight bound.
_MAX_ADMITTED_SCANS = int(os.environ.get("ARGUS_MAX_ADMITTED_SCANS", str(2 * _MAX_INFLIGHT_SCANS)))

# One shared limiter for the whole process, created at import. anyio ships with
# starlette (the `serve` extra), so it is present whenever this module is
# actually used; the guard keeps a partial install (starlette/anyio absent) from
# failing to import the module at all, matching the starlette guard above.
try:
    _scan_limiter = anyio.CapacityLimiter(_MAX_INFLIGHT_SCANS)
except NameError:  # pragma: no cover - anyio absent (serve extra not installed)
    _scan_limiter = None  # type: ignore[assignment]

# Count of scans admitted but not yet finished (running + queued) — the live
# value the `_MAX_ADMITTED_SCANS` ceiling is checked against. Incremented at
# admission and decremented in the worker's `finally`, BOTH on the single
# event-loop thread. That is what makes the check-then-increment in `_run_scan`
# race-free without a lock: no `await` sits between reading this and bumping it,
# so the loop cannot interleave two admissions and let both slip past a full
# queue. Process-global like `_scan_limiter` (a per-process bound).
_admitted_scans = 0


class _BodyTooLarge(Exception):
    """Request body exceeded MAX_HTTP_BODY_BYTES (mapped to 413)."""


class _BadBody(Exception):
    """Request body was unparseable or not a JSON object (mapped to 400)."""


class _ScanTimeout(Exception):
    """The offloaded scan exceeded _SCAN_TIMEOUT_SECONDS (mapped to 504)."""


class _ClientDisconnected(Exception):
    """The client went away before the offloaded scan finished (mapped to 499).

    While awaiting the worker, the handler also watches the request's ASGI
    receive channel; on ``http.disconnect`` it trips THIS scan's cancel token so
    the detached worker aborts at its next poll and frees its slot, then raises
    this. The caller maps it to 499 (client-closed-request) with a PII-free body.
    The transport is already gone so the response is usually discarded, but the
    handler must still return a clean, well-formed non-500 response — NEVER the
    scan result.
    """


class _ServerNotReady(Exception):
    """No scan task group — the ASGI lifespan is not active (mapped to 503).

    Raised on the bare-``create_app()`` misuse: nothing ever drove the lifespan
    that installs ``app.state.task_group``. A bare ``RuntimeError`` here would
    surface as a 500; 503 (service unavailable) is the honest status for "the
    server has not finished starting up".
    """


class _ServerBusy(Exception):
    """Admission ceiling reached: too many scans in flight (mapped to 503).

    ``_MAX_ADMITTED_SCANS`` scans are already admitted (running + queued); a
    further request is shed before its worker is spawned. PII-free by
    construction — the message is a fixed string, never request content.
    """


# One mapper for the control-signal exceptions that ONLY `_run_scan` raises. Both
# handlers (redact and restore) share this ladder verbatim, so the (status, body)
# policy lives here once instead of being hand-copied and kept "symmetric" by comment.
# Keyed by exact type — these are all leaf Exception subclasses, none a subclass of
# another, so `type(exc)` resolves unambiguously. A `None` message means "use the
# exception's own text" (the two 503s carry a fixed, PII-free message); the others use
# a fixed body. App-level exceptions (ValueError / TypeError / RestoreGuardError) are
# NOT here — each handler maps those itself, after this shared arm.
_SCAN_CONTROL_RESPONSES: dict[type, tuple[int, str | None]] = {
    _ScanTimeout: (504, "request timed out: the scan exceeded the server time limit"),
    ScanAborted: (504, "request cancelled: the scan was aborted before it completed"),
    _ClientDisconnected: (499, "client disconnected before the scan completed"),
    _ServerNotReady: (503, None),
    _ServerBusy: (503, None),
}
_SCAN_CONTROL_TYPES = tuple(_SCAN_CONTROL_RESPONSES)


def _scan_control_response(exc: BaseException) -> JSONResponse:
    """Map a `_run_scan` control-signal exception to its JSONResponse.

    `ScanAborted` reaches a handler only via the server-shutdown path (the deadline
    raises `_ScanTimeout` first, and a client disconnect raises `_ClientDisconnected`
    without reading the worker's result); it is mapped here so a shutdown-interrupted
    scan gets a clean 504 rather than a 500.
    """
    status, message = _SCAN_CONTROL_RESPONSES[type(exc)]
    return JSONResponse({"error": message or str(exc)}, status_code=status)


def _parse_json_object(raw: bytes) -> dict[str, Any]:
    """Parse a request body and require it to be a JSON **object**.

    A body like ``[1,2,3]`` / ``"hello"`` / ``42`` / ``null`` parses fine, so
    the JSONDecodeError guard never fires — but every field read after it is
    ``body.get(...)``, and ``AttributeError`` is outside the
    ``except (ValueError, TypeError)`` net the handlers rely on. That surfaced
    as a 500 while every other malformed shape returned a clean 400. Both
    body-parsing endpoints route through here so they cannot drift apart.
    """
    try:
        body = json.loads(raw)
    except ValueError:
        raise _BadBody("request body must be valid JSON") from None
    if not isinstance(body, dict):
        raise _BadBody(f"request body must be a JSON object, got {type(body).__name__}") from None
    return body


async def _read_capped_body(request: Request) -> list[bytes]:
    """Read the request body, aborting as soon as it exceeds MAX_HTTP_BODY_BYTES.

    Streams via request.stream() so memory stays bounded to ~cap even for a
    chunked body with no Content-Length header. Raises _BodyTooLarge.

    Returns the raw chunks UNJOINED: the join and JSON parse are CPU-bound on a
    body up to MAX_HTTP_BODY_BYTES and are handed to `_join_and_parse` off the
    event loop by the caller (see `_join_and_parse`). Reassembling here would
    put that cost back on the loop thread.
    """
    clen = request.headers.get("content-length")
    if clen is not None and clen.isdigit() and int(clen) > MAX_HTTP_BODY_BYTES:
        raise _BodyTooLarge
    size = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_HTTP_BODY_BYTES:
            raise _BodyTooLarge
        chunks.append(chunk)
    return chunks


def _join_and_parse(chunks: list[bytes]) -> dict[str, Any]:
    """Reassemble the streamed body and parse it as a JSON object.

    Runs OFF the event loop (the handlers dispatch it via `run_in_threadpool`):
    `b"".join` of up to MAX_HTTP_BODY_BYTES followed by `json.loads` on that
    buffer are synchronous, CPU-bound steps. Left inline on the single
    event-loop thread they would stall every OTHER concurrent request —
    including a plain `GET /health` — behind one large body. Raises `_BadBody`
    for a non-JSON or non-object body (mapped to 400 by the caller).
    """
    return _parse_json_object(b"".join(chunks))


async def _run_scan(request, fn, *, cancellable):
    """Offload a blocking core scan off the event loop under an admission
    ceiling, an in-flight bound, and an honest per-request deadline. `fn` is a
    zero-arg callable (a `functools.partial` binding redact/restore and its
    kwargs); `request` carries the app-scoped scan task group on
    `request.app.state`.

    Admission ceiling (memory-amplification backpressure): `_MAX_ADMITTED_SCANS`
    bounds TOTAL in-flight scans (running + queued). A request that would push
    the total over the ceiling is shed with a prompt 503 (`_ServerBusy`) BEFORE
    its worker is spawned, so a flood cannot queue an unbounded number of workers
    each retaining its request body/key while it waits for a slot.

    In-flight bound (a REAL resource bound): `_scan_limiter` caps how many scans
    run concurrently. The slot is acquired and released inside the detached
    `_worker` task — anyio's CapacityLimiter tracks the borrowing task, so the
    same task that acquires must release. The slot is therefore held for the
    entire lifetime of the (non-preemptible) scan thread and released EXACTLY
    ONCE as `_worker`'s `async with` unwinds, on thread COMPLETION — even on
    error or timeout, never on the client's cancelled await. This bound is
    PER-PROCESS / single-node — see the module-level note on `_scan_limiter`; a
    multi-node deployment must also bound at the gateway.

    Honest timeout (Python threads are NOT preemptible): the request awaits the
    worker's completion under `anyio.move_on_after`. When the deadline trips, the
    request returns a PROMPT 504, but the worker is NOT cancelled — the timeout
    wraps only the request's `await done.wait()`, not the worker. So the
    abandoned scan keeps running on its thread to completion and frees its slot
    only then; the deadline does NOT reclaim the CPU mid-scan. Under overload
    (all slots held by still-running scans) new requests that cannot get a slot
    within the deadline get a 504 too — honest load-shedding with a bounded
    thread count. Size the timeout and the in-flight bound accordingly, and
    rate-limit upstream. Raises `_ScanTimeout` on the deadline (mapped to 504 by
    the caller).

    Cooperative cancellation (v0.8.11): only `cancellable=True` scans get a FRESH
    per-scan `_core.CancelToken` bound into `fn`; it is tripped from any of THREE
    external events, so the detached worker aborts at its next poll and frees its
    slot early — reclaiming CPU: (1) the request deadline fires; (2) the client
    DISCONNECTS mid-scan (the handler watches the ASGI receive channel and raises
    `_ClientDisconnected` → 499); or (3) the server SHUTS DOWN (`_lifespan` trips
    every token in `app.state.live_tokens` so workers abort and the app task group
    drains promptly). Only the `/redact` fast-mode-L1 path passes `cancellable=True`
    (the only path with a cancellable `detect_l1` scan). `/restore` passes
    `cancellable=False`: no token is created, so its worker always runs to
    completion (no `detect_l1` to abort), while a disconnect/shutdown/deadline still
    ends the request promptly. This is an INTERNAL server-serving seam, not part of
    the public `redact()`/`restore()` API. The token is per-scan by construction — a
    shared or module-global token would abort unrelated in-flight scans.
    """
    global _admitted_scans

    task_group = getattr(request.app.state, "task_group", None)
    if task_group is None:
        # The scan workers are detached into the app-lifetime task group so they
        # outlive the request; without it there is nowhere to run them. The
        # lifespan installed by `create_app` sets `app.state.task_group` on
        # startup. A bare `create_app()` that no ASGI server ever drove has no
        # group — 503 (not ready), never a bare-RuntimeError 500. (getattr with a
        # default, NOT attribute access: Starlette's State raises AttributeError
        # for an unset key, which would itself surface as a 500 and defeat this.)
        raise _ServerNotReady(
            "scan task group is not running — the server lifespan must be active "
            "(create_app installs it on startup)"
        )

    # Admission ceiling BEFORE spawning a worker, so a shed request never retains
    # its body past this call. Check-then-increment is atomic under the
    # single-threaded event loop: no `await` sits between the read and the bump,
    # so two concurrent admissions cannot both observe room and both slip in.
    if _admitted_scans >= _MAX_ADMITTED_SCANS:
        raise _ServerBusy("server busy: too many scans in flight; retry shortly")
    _admitted_scans += 1

    # A FRESH cancellation token for THIS scan — never shared or module-global (a
    # shared one would abort unrelated in-flight scans). Only a `cancellable` scan
    # (the `/redact` fast-mode-L1 path) gets one, bound into `fn` so the redact scan
    # can poll it; a non-cancellable scan (`/restore`) gets token=None and skips
    # every token branch below with no other edits. Tripped in the deadline branch
    # below to reclaim CPU. Guarded on `_core` so a partial install (no compiled
    # core) does not crash here — the server needs the core to redact at all, but
    # restore-only use must not break.
    token = _core.CancelToken() if (cancellable and _core is not None) else None
    if token is not None:
        fn = functools.partial(fn, cancel_token=token)

    # Shutdown reclamation registry: `_lifespan` trips every live token on shutdown
    # so detached workers abort at their next poll and the app task group drains
    # promptly instead of blocking on abandoned scans. Reached via getattr so the
    # bare-`create_app()` misuse path (no lifespan, no registry) no-ops, matching
    # the `task_group` getattr above. The set is mutated ONLY on the single-threaded
    # event loop — added here, discarded in the `finally` below, snapshot-and-
    # cancelled in `_lifespan` — and no `await` sits between a read of it and a
    # mutation of it, so two coroutines can never interleave a mutation across a
    # checkpoint; a plain `set` is therefore race-free without a lock. `discard`
    # (never `remove`) so a double-drain — shutdown clearing the registry while this
    # scan is still unwinding — never raises.
    live_tokens = getattr(request.app.state, "live_tokens", None)
    if token is not None and live_tokens is not None:
        live_tokens.add(token)

    done = anyio.Event()
    holder: dict[str, Any] = {}

    async def _worker() -> None:
        global _admitted_scans
        try:
            # Acquire AND release are both bound to this worker task's lifetime.
            # The slot frees exactly once, as this `async with` unwinds — i.e. on
            # thread completion — even when the scan raises. Do NOT move the
            # acquire/release out of the worker or bypass the context manager, or
            # a slot leaks and capacity is permanently lost.
            async with _scan_limiter:
                try:
                    holder["value"] = await to_thread.run_sync(fn)
                except Exception as exc:  # noqa: BLE001 - forwarded to the request task
                    # NOT BaseException: a real cancellation must propagate so the
                    # task group can tear the worker down. App-level exceptions
                    # (ValueError / RestoreGuardError / …) are forwarded to the
                    # awaiting request, which re-raises them for the handler to map.
                    holder["error"] = exc
                finally:
                    # Wake the waiter even on error/cancel; the slot is released
                    # as this `async with` unwinds, on real thread completion.
                    done.set()
        finally:
            # Release the admission slot on REAL worker completion (ran or
            # errored), mirroring the increment at admission. This is the only
            # decrement, so the counter cannot drift below or above the true
            # in-flight count.
            _admitted_scans -= 1

    try:
        task_group.start_soon(_worker)

        # Await the worker AND watch for the client going away, under the deadline.
        # The host body awaits the worker while a single child watches for a client
        # disconnect; whichever fires first cancels the inner group, and the outer
        # `move_on_after` still owns the deadline. This is byte-identical to the old
        # bare `await done.wait()` when the client never disconnects — the disconnect
        # watcher simply parks (see `_watch_disconnect`) and is cancelled the instant
        # the worker completes or the deadline fires.
        disconnected = False
        with anyio.move_on_after(_SCAN_TIMEOUT_SECONDS) as scope:
            async with anyio.create_task_group() as inner_tg:

                async def _watch_disconnect() -> None:
                    # No polling: the handler fully read the request body before
                    # `_run_scan`, so `request.receive` now only yields the disconnect
                    # event — the await BLOCKS with zero CPU cost until the ASGI
                    # server delivers `http.disconnect`, and detects it promptly. On
                    # disconnect, trip THIS scan's token (so the detached worker
                    # aborts and frees its slot) and cancel the inner group so the
                    # handler stops waiting. The worker's own `done.set()` then lands
                    # in a holder nobody reads — correct: the client is gone, so we
                    # never block on or read `holder` here.
                    nonlocal disconnected
                    receive = getattr(request, "receive", None)
                    if receive is None:  # no ASGI receive channel (non-HTTP caller)
                        return
                    while True:
                        message = await receive()
                        if message.get("type") == "http.disconnect":
                            break
                    disconnected = True
                    if token is not None:
                        token.cancel()
                    inner_tg.cancel_scope.cancel()

                # The host body is itself a task in the inner group's cancel scope, so
                # awaiting the worker here and cancelling directly is equivalent to a
                # second child doing it — minus a coroutine. Worker finishes -> this
                # await returns -> the cancel tears down the watcher; client
                # disconnects -> the watcher cancels the scope -> this await is
                # cancelled and the group exits; deadline -> the outer `move_on_after`
                # cancels the whole inner group.
                inner_tg.start_soon(_watch_disconnect)
                await done.wait()
                inner_tg.cancel_scope.cancel()

        if scope.cancelled_caught:
            # Deadline hit: trip the token (fire-and-forget) so the detached worker
            # aborts at its next detect_l1 poll and frees its slot EARLY, reclaiming
            # CPU — instead of running the abandoned scan to completion. The client
            # still gets a prompt 504 now; the worker's ScanAborted is caught by its
            # own `except Exception` and never surfaces here (see the module note on
            # ScanAborted). A `/restore` scan drops the token, so it is unaffected.
            if token is not None:
                token.cancel()
            raise _ScanTimeout
        if disconnected:
            # Client went away mid-scan. The token is already tripped by the watcher;
            # re-trip idempotently for safety. Do NOT read `holder` — the worker
            # aborts on its own next poll into a holder nobody reads. Raise a clean,
            # PII-free 499 — never the scan result, never a 500.
            if token is not None:
                token.cancel()
            raise _ClientDisconnected("client disconnected before the scan completed")
        if "error" in holder:
            raise holder["error"]
        return holder["value"]
    finally:
        # Drain THIS scan's token from the shutdown registry on EVERY exit path
        # (returned, timed out, disconnected, errored). `discard` never raises even
        # if `_lifespan` already cleared the registry underneath us on shutdown.
        if token is not None and live_tokens is not None:
            live_tokens.discard(token)


async def handle_redact(request: Request) -> JSONResponse:
    try:
        chunks = await _read_capped_body(request)
    except _BodyTooLarge:
        return JSONResponse({"error": "request body too large"}, status_code=413)

    # A malformed/empty body raises JSONDecodeError (a ValueError), and a valid
    # non-object body would break on the first `.get` — both surface as _BadBody
    # and map to 400. The join+parse are offloaded so a large body cannot stall
    # the event loop (see `_join_and_parse`).
    try:
        body = await run_in_threadpool(_join_and_parse, chunks)
    except _BadBody as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    text = body.get("text", "")
    lang = body.get("lang", "zh")
    mode = body.get("mode", "fast")
    salt = body.get("salt")
    config = body.get("config")
    # Security: reject config as file path string (only dicts allowed via HTTP)
    if isinstance(config, str):
        return JSONResponse(
            {"error": "config must be a JSON object, not a file path"},
            status_code=400,
        )
    key = body.get("key")
    # Security: reject any non-dict, non-None key (str path, list, int, etc.)
    if key is not None and not isinstance(key, dict):
        return JSONResponse(
            {"error": "key must be a JSON object"},
            status_code=400,
        )
    if key is not None and len(key) > MAX_RESTORE_KEY_ENTRIES:
        return JSONResponse(
            {"error": f"key too large: {len(key)} entries exceeds {MAX_RESTORE_KEY_ENTRIES}"},
            status_code=413,
        )
    detailed = body.get("detailed", False)
    report = body.get("report", False)
    profile = body.get("profile")
    types = body.get("types")
    types_exclude = body.get("types_exclude")

    # Offloaded to a threadpool thread under `_run_scan`: the Rust core releases
    # the GIL while it scans (py.detach in the bindings), but that only helps if
    # something else can run on the event-loop thread while the scan is in
    # flight. Called inline, the `async def` handler still blocked the single
    # event-loop thread for the full scan, stalling every OTHER concurrent
    # request — including a plain GET /health — behind one expensive /redact
    # call. `_run_scan` also enforces the in-flight bound and the honest 504
    # deadline (see its docstring).
    try:
        # The cancellable path uses the internal `_redact_impl` (NOT the public
        # `redact`, whose frozen Layer-1 signature has no `cancel_token`): `_run_scan`
        # binds a fresh per-scan token into this partial when `cancellable=True`.
        result = await _run_scan(
            request,
            functools.partial(
                _redact_impl,
                text,
                lang=lang,
                mode=mode,
                salt=salt,
                config=config,
                key=key,
                detailed=detailed,
                report=report,
                profile=profile,
                types=types,
                types_exclude=types_exclude,
            ),
            cancellable=True,
        )
    except _SCAN_CONTROL_TYPES as e:
        return _scan_control_response(e)
    except (ValueError, TypeError) as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    if report:
        return JSONResponse(
            {
                "redacted": result.redacted_text,
                "key": result.key,
                "entities": list(result.entities),
                "stats": result.stats,
                "risk": risk_payload(result.risk),
                **common_report_fields(result),
            }
        )

    if detailed:
        redacted, result_key, details = result
        return JSONResponse(
            {
                "redacted": redacted,
                "key": result_key,
                "details": details,
            }
        )

    redacted, result_key = result
    return JSONResponse({"redacted": redacted, "key": result_key})


async def handle_restore(request: Request) -> JSONResponse:
    try:
        chunks = await _read_capped_body(request)
    except _BodyTooLarge:
        return JSONResponse({"error": "request body too large"}, status_code=413)

    # A malformed body raises JSONDecodeError (a ValueError), and a valid
    # non-object body would break on the first `.get` — both surface as _BadBody
    # and map to 400. The join+parse are offloaded so a large body cannot stall
    # the event loop (see `_join_and_parse`).
    try:
        body = await run_in_threadpool(_join_and_parse, chunks)
    except _BadBody as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    text = body.get("text", "")
    key = body.get("key", {})
    # Security: reject any non-dict, non-None key (str path, list, int, etc.)
    if key is not None and not isinstance(key, dict):
        return JSONResponse(
            {"error": "key must be a JSON object"},
            status_code=400,
        )
    # Size cap on the key itself — see MAX_RESTORE_KEY_ENTRIES. 413 (not 400)
    # because this is the same class of refusal as the body cap: the request is
    # well-formed, it is too big.
    if key is not None and len(key) > MAX_RESTORE_KEY_ENTRIES:
        return JSONResponse(
            {"error": f"key too large: {len(key)} entries exceeds {MAX_RESTORE_KEY_ENTRIES}"},
            status_code=413,
        )

    # v0.8.0: guard defaults to True — a restore with no anchor fails closed. A
    # caller wanting the legacy plain substitution passes "guard": false.
    guard = body.get("guard", True)
    strict = body.get("strict", False)

    # Optional `{fake: [alternate-transliteration, ...]}` map — mirrors
    # `restore(text, key, aliases=...)`, so an LLM reply that rewrote a fake
    # into one of its aliases still round-trips over HTTP. Values must be
    # lists of strings — a bare string would otherwise iterate
    # character-by-character once handed to `restore()` (the same footgun
    # `anchor.scope` below guards against). This duplicates part of
    # `restore()`'s own `_normalize_aliases` seam deliberately: checking here,
    # ahead of `_run_scan`, keeps a malformed body a deterministic 400 instead
    # of possibly riding the CapacityLimiter/deadline into a 504 under load.
    aliases = body.get("aliases")
    if aliases is not None:
        if not isinstance(aliases, dict):
            return JSONResponse({"error": "aliases must be a JSON object"}, status_code=400)
        if not all(
            isinstance(v, list) and all(isinstance(item, str) for item in v)
            for v in aliases.values()
        ):
            return JSONResponse(
                {"error": "aliases values must be lists of alias strings"},
                status_code=400,
            )

    # Optional display marker — mirrors `restore(text, key, display_marker=...)`:
    # stripped from `text` before key lookup (e.g. a visible "ⓕ" decoration).
    display_marker = body.get("display_marker")
    if display_marker is not None and not isinstance(display_marker, str):
        return JSONResponse({"error": "display_marker must be a string"}, status_code=400)

    # Optional provenance/scope anchor: {"nonce": str, "scope": [pseudonym, ...]}.
    # Reconstructed into the same Anchor make_anchor() produces so the (P + S)
    # checks in restore() can verify the model echoed the nonce and stayed in scope.
    anchor = None
    anchor_spec = body.get("anchor")
    if anchor_spec is not None:
        if not isinstance(anchor_spec, dict):
            return JSONResponse(
                {"error": "anchor must be a JSON object with nonce and scope"},
                status_code=400,
            )
        nonce = anchor_spec.get("nonce", "")
        scope = anchor_spec.get("scope", [])
        # Security: reject a non-str nonce and a non-list scope up front. A str
        # scope (e.g. "P-1") would otherwise pass frozenset() silently and become
        # frozenset({'P', '-', '1'}) — garbage that still "succeeds" with a 200.
        if not isinstance(nonce, str):
            return JSONResponse({"error": "anchor.nonce must be a string"}, status_code=400)
        if not isinstance(scope, list):
            return JSONResponse(
                {"error": "anchor.scope must be a list of pseudonym strings"},
                status_code=400,
            )

    try:
        # Anchor construction lives inside the try too: even a list scope can
        # contain an unhashable element (e.g. a nested list), which raises inside
        # frozenset() — that must map to 400 via the except below, not an
        # unhandled 500.
        if anchor_spec is not None:
            from argus_redact.compose.anchor import Anchor

            anchor = Anchor(nonce=nonce, scope=frozenset(scope))
        # Offloaded under `_run_scan` — see the matching comment in
        # handle_redact: the inline call blocked the event loop for every
        # concurrent request while this one scanned. `_run_scan` also enforces
        # the in-flight bound and the honest 504 deadline (see its docstring).
        restored, details = await _run_scan(
            request,
            functools.partial(
                restore,
                text,
                key,
                aliases=aliases,
                display_marker=display_marker,
                guard=guard,
                anchor=anchor,
                strict=strict,
                detailed=True,
            ),
            cancellable=False,
        )
    except _SCAN_CONTROL_TYPES as e:
        return _scan_control_response(e)
    except RestoreGuardError as e:
        return JSONResponse({"error": str(e), "security_events": e.events}, status_code=400)
    except (ValueError, TypeError) as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    return JSONResponse(
        {"restored": restored, "security_events": details.get("security_events", [])}
    )


async def handle_info(request: Request) -> JSONResponse:
    # Derive the language list from the shipped-pack SSOT (_LANG_PATTERNS) and
    # display names from the same single source the CLI `cmd_info` uses, so a
    # newly-added pack appears on both surfaces without a second hand-edit.
    from argus_redact.glue.redact import _LANG_DISPLAY_NAMES, _LANG_PATTERNS
    from argus_redact.lang.shared.patterns import PATTERNS as SHARED

    lang_info: dict[str, Any] = {}

    for code in _LANG_PATTERNS:
        mod_code = "in_" if code == "in" else code
        try:
            mod = importlib.import_module(f"argus_redact.lang.{mod_code}.patterns")
            count = len(mod.PATTERNS) + len(SHARED)
        except ModuleNotFoundError:
            count = 0

        has_ner = importlib.util.find_spec(f"argus_redact.lang.{mod_code}.ner_adapter") is not None

        lang_info[code] = {
            "name": _LANG_DISPLAY_NAMES.get(code, code),
            "patterns": count,
            "ner": has_ner,
        }

    return JSONResponse(
        {
            "version": __version__,
            "languages": lang_info,
        }
    )


async def handle_health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def _auth_middleware(app):
    """Optional API key auth. Set ARGUS_API_KEY env var to enable."""
    api_key = os.environ.get("ARGUS_API_KEY")
    if not api_key:
        return app

    # Endpoints that don't require auth
    _PUBLIC_PATHS = {"/health"}

    async def middleware(scope, receive, send):
        if scope["type"] == "http" and scope["path"] not in _PUBLIC_PATHS:
            from starlette.requests import Request
            from starlette.responses import JSONResponse

            request = Request(scope, receive)
            auth = request.headers.get("authorization", "")
            expected = f"Bearer {api_key}".encode("utf-8")
            provided = auth.encode("utf-8") if auth else b""
            if not secrets.compare_digest(provided, expected):
                response = JSONResponse(
                    {"error": "Unauthorized. Set Authorization: Bearer <ARGUS_API_KEY>"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return
        await app(scope, receive, send)

    return middleware


def create_app(*, allow_no_auth: bool = False):
    """Create Starlette ASGI app. Requires: pip install argus-redact[serve].

    Refuses to start when ``ARGUS_API_KEY`` is unset (the ``/restore``
    endpoint exposes PII recovery — running it open to the network is unsafe).
    Pass ``allow_no_auth=True`` (CLI: ``--insecure``) for local development;
    a ``SecurityWarning`` is emitted in that case.
    """
    from starlette.applications import Starlette
    from starlette.routing import Route

    @contextlib.asynccontextmanager
    async def _lifespan(app):
        # App-lifetime task group that owns detached scan workers. Holding it
        # open across `yield` lets handlers `start_soon` workers that OUTLIVE
        # their request (so a timed-out request's worker keeps its slot until the
        # scan finishes). Exiting it on shutdown WAITS for every started worker to
        # complete; the running scans are on non-preemptible threads, so before the
        # drain the shutdown branch below trips every in-flight scan's cancel token
        # (see `live_tokens`) — each worker then aborts at its next poll rather than
        # running its abandoned scan to completion, so the drain is prompt instead
        # of blocking on discarded work. It lives on `app.state` (NOT a module
        # global) so each app owns its own group — two apps in one process (a
        # test suite, an embedding host) never share or clobber one another's.
        # Cleared to None (not delattr) before the drain so a late scan fails fast
        # with 503 instead of racing a closing group; handlers reach it via
        # `getattr(request.app.state, "task_group", None)`.
        async with anyio.create_task_group() as tg:
            app.state.task_group = tg
            # Registry of the in-flight per-scan cancel tokens `_run_scan` admits.
            # Mutated only on the single-threaded event loop (add/discard in
            # `_run_scan`, snapshot-and-cancel here), so a plain `set` is race-free
            # without a lock. Lives on `app.state` for the same per-app isolation as
            # the task group.
            app.state.live_tokens = set()
            try:
                yield
            finally:
                # Shutdown reclamation: trip EVERY in-flight scan's token BEFORE the
                # `async with tg` teardown below waits on the detached workers, so
                # each aborts at its next poll and the drain stays prompt. Cancel
                # over a SNAPSHOT (`list(...)`) — cancelling does not touch the set,
                # so this cannot race a concurrent `discard` from a finishing
                # `_run_scan`. Cleared to None alongside the task group (not delattr).
                live = app.state.live_tokens
                if live:
                    for scan_token in list(live):
                        scan_token.cancel()
                app.state.task_group = None
                app.state.live_tokens = None

    api_key = os.environ.get("ARGUS_API_KEY")
    if not api_key and not allow_no_auth:
        raise RuntimeError(
            "Set ARGUS_API_KEY for Bearer-token auth, or pass allow_no_auth=True "
            "(CLI: --insecure) for local dev."
        )
    if not api_key and allow_no_auth:
        warnings.warn(
            "argus-redact server running with no auth (allow_no_auth=True). "
            "Anyone reaching the listening port can call /redact and /restore.",
            SecurityWarning,
            stacklevel=2,
        )

    routes = [
        Route("/redact", handle_redact, methods=["POST"]),
        Route("/restore", handle_restore, methods=["POST"]),
        Route("/info", handle_info, methods=["GET"]),
        Route("/health", handle_health, methods=["GET"]),
    ]
    app = Starlette(routes=routes, lifespan=_lifespan)
    return _auth_middleware(app)


def main():
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="argus-redact HTTP API server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Run without ARGUS_API_KEY auth (local development only).",
    )
    args = parser.parse_args()

    app = create_app(allow_no_auth=args.insecure)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
