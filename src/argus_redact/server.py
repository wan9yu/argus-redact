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

try:
    from starlette.requests import Request
    from starlette.responses import JSONResponse
except ImportError:
    if TYPE_CHECKING:
        from starlette.requests import Request
        from starlette.responses import JSONResponse

# Configurable server-side body cap — a DoS guard against memory amplification
# from unbounded request bodies buffered before any size check.
MAX_HTTP_BODY_BYTES = 10 * 1024 * 1024


class _BodyTooLarge(Exception):
    """Request body exceeded MAX_HTTP_BODY_BYTES (mapped to 413)."""


async def _read_capped_body(request: Request) -> bytes:
    """Read the request body, aborting as soon as it exceeds MAX_HTTP_BODY_BYTES.

    Streams via request.stream() so memory stays bounded to ~cap even for a
    chunked body with no Content-Length header. Raises _BodyTooLarge.
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
    return b"".join(chunks)


async def handle_redact(request: Request) -> JSONResponse:
    try:
        raw = await _read_capped_body(request)
    except _BodyTooLarge:
        return JSONResponse({"error": "request body too large"}, status_code=413)

    # C4: a malformed/empty body raises JSONDecodeError (a ValueError). Parsing
    # inside the try turns that into a 400, not an unhandled 500.
    try:
        body = json.loads(raw)
    except ValueError:
        return JSONResponse({"error": "request body must be valid JSON"}, status_code=400)

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
    detailed = body.get("detailed", False)
    report = body.get("report", False)
    profile = body.get("profile")
    types = body.get("types")
    types_exclude = body.get("types_exclude")

    try:
        result = redact(
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
    except (ValueError, TypeError) as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    if report:
        return JSONResponse(
            {
                "redacted": result.redacted_text,
                "key": result.key,
                "entities": list(result.entities),
                "stats": result.stats,
                "risk": {
                    "score": result.risk.score,
                    "level": result.risk.level,
                    "reasons": list(result.risk.reasons),
                    "pipl_articles": list(result.risk.pipl_articles),
                },
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
        raw = await _read_capped_body(request)
    except _BodyTooLarge:
        return JSONResponse({"error": "request body too large"}, status_code=413)

    # C4: a malformed body raises JSONDecodeError (a ValueError). Parsing inside
    # the try turns that into a 400, not an unhandled 500.
    try:
        body = json.loads(raw)
    except ValueError:
        return JSONResponse({"error": "request body must be valid JSON"}, status_code=400)

    text = body.get("text", "")
    key = body.get("key", {})
    # Security: reject any non-dict, non-None key (str path, list, int, etc.)
    if key is not None and not isinstance(key, dict):
        return JSONResponse(
            {"error": "key must be a JSON object"},
            status_code=400,
        )

    # v0.8.0: guard defaults to True — a restore with no anchor fails closed. A
    # caller wanting the legacy plain substitution passes "guard": false.
    guard = body.get("guard", True)
    strict = body.get("strict", False)

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
        restored, details = restore(
            text, key, guard=guard, anchor=anchor, strict=strict, detailed=True
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
    app = Starlette(routes=routes)
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
