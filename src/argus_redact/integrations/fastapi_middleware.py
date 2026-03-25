"""FastAPI integration — redact_body / restore_body helpers and optional middleware.

No FastAPI dependency required for the helper functions.

Usage (endpoint-level):
    from argus_redact.integrations.fastapi_middleware import redact_body, restore_body

    @app.post("/chat")
    async def chat(req: Request):
        body = await req.json()
        redacted, key = redact_body(body, mode="fast", lang="zh")
        llm_output = call_llm(redacted["text"])
        restored = restore_body({"result": llm_output}, key, field="result")
        return restored

Usage (middleware):
    from argus_redact.integrations.fastapi_middleware import RedactMiddleware

    app.add_middleware(RedactMiddleware, lang="zh", mode="fast")
"""

from __future__ import annotations

from argus_redact import redact, restore


def redact_body(
    body: dict,
    *,
    field: str = "text",
    mode: str = "fast",
    lang: str | list[str] = "zh",
    seed: int | None = None,
) -> tuple[dict, dict]:
    """Redact PII in a request body dict.

    Looks for `field` in body. If field is "messages", redacts each
    message's "content". Returns (redacted_body, key).
    """
    result = dict(body)
    combined_key: dict = {}

    if field == "messages" and "messages" in body:
        redacted_messages = []
        for msg in body["messages"]:
            if isinstance(msg, dict) and "content" in msg:
                new_msg = dict(msg)
                redacted_text, combined_key = redact(
                    msg["content"],
                    mode=mode,
                    lang=lang,
                    seed=seed,
                    key=combined_key if combined_key else None,
                )
                new_msg["content"] = redacted_text
                redacted_messages.append(new_msg)
            else:
                redacted_messages.append(msg)
        result["messages"] = redacted_messages
    elif field in body and isinstance(body[field], str):
        redacted_text, combined_key = redact(
            body[field],
            mode=mode,
            lang=lang,
            seed=seed,
        )
        result[field] = redacted_text
    else:
        return result, {}

    return result, combined_key


def restore_body(
    response: dict | str,
    key: dict,
    *,
    field: str | None = None,
) -> dict | str:
    """Restore PII in a response body.

    If response is a string, restore directly.
    If response is a dict, restore the specified field.
    """
    if not key:
        return response

    if isinstance(response, str):
        return restore(response, key)

    if isinstance(response, dict) and field and field in response:
        result = dict(response)
        result[field] = restore(str(response[field]), key)
        return result

    return response


class RedactMiddleware:
    """ASGI middleware placeholder for FastAPI.

    For production use, implement as proper Starlette BaseHTTPMiddleware.
    See docstring at module level for endpoint-level usage (recommended).
    """

    def __init__(self, app, *, lang="zh", mode="fast"):
        self.app = app
        self.lang = lang
        self.mode = mode
