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
import os
from typing import TYPE_CHECKING, Any

from argus_redact import __version__, redact, restore

try:
    from starlette.requests import Request
    from starlette.responses import JSONResponse
except ImportError:
    if TYPE_CHECKING:
        from starlette.requests import Request
        from starlette.responses import JSONResponse


async def handle_redact(request: Request) -> JSONResponse:
    body = await request.json()
    text = body.get("text", "")
    lang = body.get("lang", "zh")
    mode = body.get("mode", "fast")
    seed = body.get("seed")
    config = body.get("config")
    # Security: reject config as file path string (only dicts allowed via HTTP)
    if isinstance(config, str):
        return JSONResponse(
            {"error": "config must be a JSON object, not a file path"},
            status_code=400,
        )
    key = body.get("key")
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
            seed=seed,
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
    body = await request.json()
    text = body.get("text", "")
    key = body.get("key", {})

    try:
        restored = restore(text, key)
    except (ValueError, TypeError) as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    return JSONResponse({"restored": restored})


async def handle_info(request: Request) -> JSONResponse:
    from argus_redact.lang.shared.patterns import PATTERNS as SHARED

    langs: dict[str, str] = {
        "zh": "Chinese",
        "en": "English",
        "ja": "Japanese",
        "ko": "Korean",
        "de": "German",
        "uk": "British English",
        "in": "Indian",
        "br": "Brazilian Portuguese",
    }
    lang_info: dict[str, Any] = {}

    for code, name in langs.items():
        mod_path = f"argus_redact.lang.{code}.patterns"
        if code == "in":
            mod_path = "argus_redact.lang.in_.patterns"
        try:
            mod = importlib.import_module(mod_path)
            count = len(mod.PATTERNS) + len(SHARED)
        except ModuleNotFoundError:
            count = 0

        ner_path = f"argus_redact.lang.{code}.ner_adapter"
        if code == "in":
            ner_path = "argus_redact.lang.in_.ner_adapter"
        has_ner = importlib.util.find_spec(ner_path) is not None

        lang_info[code] = {"name": name, "patterns": count, "ner": has_ner}

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
            if auth != f"Bearer {api_key}":
                response = JSONResponse(
                    {"error": "Unauthorized. Set Authorization: Bearer <ARGUS_API_KEY>"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return
        await app(scope, receive, send)

    return middleware


def create_app():
    """Create Starlette ASGI app. Requires: pip install argus-redact[serve]"""
    from starlette.applications import Starlette
    from starlette.routing import Route

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
    args = parser.parse_args()

    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
