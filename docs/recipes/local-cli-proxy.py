#!/usr/bin/env python3
"""argus-redact local CLI proxy — reference implementation.

A ~150-line OpenAI-compatible HTTP proxy that intercepts requests,
redacts PII in messages[], forwards to a configured upstream
(DeepSeek / OpenAI / Kimi / Zhipu / any OpenAI-shape API), then restores
PII in the response on the way back.

This is a RECIPE, not a product. Copy-paste, modify, run. See the
companion local-cli-proxy.md for limitations and use cases.

Usage:
    pip install argus-redact[serve]
    export UPSTREAM_API_KEY=sk-deepseek-...
    python local-cli-proxy.py

Then point any OpenAI-compatible client at the proxy:
    export OPENAI_API_BASE=http://localhost:11434/v1
    export OPENAI_API_KEY=anything   # ignored; proxy uses UPSTREAM_API_KEY
    llm -m deepseek-chat "summarize ~/notes/diary.md"

Environment variables:
    PORT              default 11434 (matches Ollama-style local LLM convention)
    UPSTREAM_BASE     default https://api.deepseek.com/v1
    UPSTREAM_API_KEY  REQUIRED — forwarded as Bearer to upstream
    REDACT_LANG       default "zh,en"  (comma-separated)
    REDACT_MODE       default "fast"   (fast | ner | auto)
"""
from __future__ import annotations

import json
import os
import sys

import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from argus_redact import redact, restore

PORT = int(os.environ.get("PORT", "11434"))
UPSTREAM_BASE = os.environ.get("UPSTREAM_BASE", "https://api.deepseek.com/v1").rstrip("/")
UPSTREAM_API_KEY = os.environ.get("UPSTREAM_API_KEY", "")
REDACT_LANG = os.environ.get("REDACT_LANG", "zh,en")
REDACT_MODE = os.environ.get("REDACT_MODE", "fast")

if not UPSTREAM_API_KEY:
    sys.exit("UPSTREAM_API_KEY not set. Export your upstream API key first.")

LANGS = [code.strip() for code in REDACT_LANG.split(",") if code.strip()]


def _redact_messages(messages: list[dict]) -> tuple[list[dict], dict]:
    """Redact PII in every message's content. Single shared key dict so the
    same original value gets the same pseudonym across system / user / assistant
    messages in this request."""
    key: dict = {}
    out: list[dict] = []
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str) and content:
            redacted, key = redact(content, lang=LANGS, mode=REDACT_MODE, key=key)
            msg = {**msg, "content": redacted}
        out.append(msg)
    return out, key


def _restore_sse_line(line: str, key: dict) -> str:
    """Restore PII inside a single SSE data: line. Returns the rewritten line
    (with trailing newline preserved). Non-data lines pass through unchanged.

    Caveat: a long pseudonym split across two SSE chunks (rare in practice;
    OpenAI/DeepSeek deltas typically fit a token) would slip the per-chunk
    restore. For stricter guarantees, swap this for argus_redact.streaming
    StreamingRestorer (sentence-buffered). See local-cli-proxy.md §Limitations.
    """
    if not line.startswith("data: "):
        return line
    payload_str = line[6:].rstrip()
    if payload_str == "[DONE]":
        return line
    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        return line
    choices = payload.get("choices") or []
    for choice in choices:
        delta = choice.get("delta") or {}
        content = delta.get("content")
        if isinstance(content, str) and content:
            delta["content"] = restore(content, key)
        # also restore on non-streaming-style choices (some upstreams mix)
        msg = choice.get("message") or {}
        content = msg.get("content")
        if isinstance(content, str) and content:
            msg["content"] = restore(content, key)
    return "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"


async def chat_completions(request):
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse({"error": {"message": f"invalid JSON: {e}"}}, status_code=400)

    # v1 doesn't support tool_use — redact/restore on tool args/results is a
    # stateful problem we punt on. Reject explicitly so the caller knows.
    for forbidden in ("tools", "tool_choice", "functions", "function_call"):
        if forbidden in body:
            return JSONResponse(
                {
                    "error": {
                        "message": (
                            "argus-redact local proxy v1 does not support "
                            f"tool_use (saw `{forbidden}` in request). Remove "
                            "tools/functions from your request, or use the "
                            "upstream API directly."
                        ),
                        "type": "unsupported_in_recipe",
                    }
                },
                status_code=400,
            )

    messages = body.get("messages") or []
    redacted_messages, key = _redact_messages(messages)
    body["messages"] = redacted_messages

    upstream_url = f"{UPSTREAM_BASE}/chat/completions"
    headers = {
        "Authorization": f"Bearer {UPSTREAM_API_KEY}",
        "Content-Type": "application/json",
    }
    is_stream = bool(body.get("stream"))

    if is_stream:
        async def gen():
            async with httpx.AsyncClient(timeout=300) as client:
                async with client.stream("POST", upstream_url, json=body, headers=headers) as resp:
                    if resp.status_code != 200:
                        err_body = await resp.aread()
                        yield err_body
                        return
                    async for raw_line in resp.aiter_lines():
                        rewritten = _restore_sse_line(raw_line + "\n", key)
                        yield rewritten.encode("utf-8")

        return StreamingResponse(gen(), media_type="text/event-stream")

    # Non-streaming path
    async with httpx.AsyncClient(timeout=300) as client:
        upstream_resp = await client.post(upstream_url, json=body, headers=headers)
    if upstream_resp.status_code != 200:
        try:
            return JSONResponse(upstream_resp.json(), status_code=upstream_resp.status_code)
        except Exception:
            return JSONResponse(
                {"error": {"message": upstream_resp.text}},
                status_code=upstream_resp.status_code,
            )

    data = upstream_resp.json()
    for choice in data.get("choices") or []:
        msg = choice.get("message") or {}
        if isinstance(msg.get("content"), str) and msg["content"]:
            msg["content"] = restore(msg["content"], key)
    return JSONResponse(data)


app = Starlette(routes=[Route("/v1/chat/completions", chat_completions, methods=["POST"])])


if __name__ == "__main__":
    import uvicorn

    print(f"argus-redact local CLI proxy")
    print(f"  upstream:  {UPSTREAM_BASE}")
    print(f"  mode:      {REDACT_MODE}")
    print(f"  langs:     {LANGS}")
    print(f"  listening: http://localhost:{PORT}")
    print()
    print(f"Point any OpenAI-compatible client at this proxy:")
    print(f"  export OPENAI_API_BASE=http://localhost:{PORT}/v1")
    print(f"  export OPENAI_API_KEY=anything")
    print()
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
