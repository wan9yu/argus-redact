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

from argus_redact import __version__, redact, restore
from argus_redact.exceptions import SecurityWarning
from argus_redact.pure.restore import RestoreGuardError
from argus_redact.pure.wire import common_report_fields, risk_payload

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

# One shared limiter for the whole process, created at import. anyio ships with
# starlette (the `serve` extra), so it is present whenever this module is
# actually used; the guard keeps a partial install (starlette/anyio absent) from
# failing to import the module at all, matching the starlette guard above.
try:
    _scan_limiter = anyio.CapacityLimiter(_MAX_INFLIGHT_SCANS)
except NameError:  # pragma: no cover - anyio absent (serve extra not installed)
    _scan_limiter = None  # type: ignore[assignment]

# The app-lifetime task group that owns detached scan workers. Created and held
# open by the Starlette lifespan (see `create_app`) and torn down on shutdown, so
# a worker OUTLIVES the request that spawned it: a timed-out request returns 504
# while its worker keeps running on a thread and releases its slot only on
# completion. None until the lifespan starts (and again after shutdown).
_APP_TASK_GROUP = None


class _BodyTooLarge(Exception):
    """Request body exceeded MAX_HTTP_BODY_BYTES (mapped to 413)."""


class _BadBody(Exception):
    """Request body was unparseable or not a JSON object (mapped to 400)."""


class _ScanTimeout(Exception):
    """The offloaded scan exceeded _SCAN_TIMEOUT_SECONDS (mapped to 504)."""


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


async def _run_scan(fn):
    """Offload a blocking core scan off the event loop under an in-flight bound
    and an honest per-request deadline. `fn` is a zero-arg callable (a
    `functools.partial` binding redact/restore and its kwargs).

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

    Cooperative cancellation that reclaims CPU at the deadline is planned for a
    future release.
    """
    if _APP_TASK_GROUP is None:  # pragma: no cover - misuse outside the ASGI lifespan
        # The scan workers are detached into the app-lifetime task group so they
        # outlive the request; without it there is nowhere to run them. The
        # lifespan installed by `create_app` sets this on startup.
        raise RuntimeError(
            "scan task group is not running — the server lifespan must be active "
            "(create_app installs it on startup)"
        )

    done = anyio.Event()
    holder: dict[str, Any] = {}

    async def _worker() -> None:
        # Acquire AND release are both bound to this worker task's lifetime. The
        # slot frees exactly once, as this `async with` unwinds — i.e. on thread
        # completion — even when the scan raises. Do NOT move the acquire/release
        # out of the worker or bypass the context manager, or a slot leaks and
        # capacity is permanently lost.
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
                # Wake the waiter even on error/cancel; the slot is released as
                # this `async with` unwinds, on real thread completion.
                done.set()

    _APP_TASK_GROUP.start_soon(_worker)
    with anyio.move_on_after(_SCAN_TIMEOUT_SECONDS) as scope:
        await done.wait()
    if scope.cancelled_caught:
        # Deadline hit: the worker keeps running, still holds its slot, and frees
        # it on completion. The client gets a prompt 504.
        raise _ScanTimeout
    if "error" in holder:
        raise holder["error"]
    return holder["value"]


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
        result = await _run_scan(
            functools.partial(
                redact,
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
            )
        )
    except _ScanTimeout:
        return JSONResponse(
            {"error": "request timed out: the scan exceeded the server time limit"},
            status_code=504,
        )
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
    # lists: a bare string value would otherwise iterate character-by-character
    # once handed to `restore()` (the same footgun `anchor.scope` below guards
    # against), silently building garbage single-character aliases.
    aliases = body.get("aliases")
    if aliases is not None:
        if not isinstance(aliases, dict):
            return JSONResponse({"error": "aliases must be a JSON object"}, status_code=400)
        if not all(isinstance(v, list) for v in aliases.values()):
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
            )
        )
    except _ScanTimeout:
        return JSONResponse(
            {"error": "request timed out: the scan exceeded the server time limit"},
            status_code=504,
        )
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
        # scan finishes). Exiting it on shutdown WAITS for every started worker
        # to complete: the running scans are on non-preemptible threads and are
        # not cancelled, so graceful shutdown drains in-flight (and queued) scans
        # rather than abandoning them. `_APP_TASK_GROUP` is cleared before the
        # drain so a late request fails fast instead of racing a closing group.
        global _APP_TASK_GROUP
        async with anyio.create_task_group() as tg:
            _APP_TASK_GROUP = tg
            try:
                yield
            finally:
                _APP_TASK_GROUP = None

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
