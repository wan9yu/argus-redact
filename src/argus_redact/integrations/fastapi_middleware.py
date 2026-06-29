"""FastAPI / Starlette integration helpers.

No FastAPI dependency required for the helper functions.

Recommended pattern: call ``redact_body()`` at the endpoint boundary
(POST/PUT handlers that accept user-submitted text). This gives explicit
control over which fields are redacted and which are passed through, and
surfaces the key dict to the caller for later ``restore_body()``.

Usage (endpoint-level):
    from argus_redact.integrations.fastapi_middleware import redact_body, restore_body

    @app.post("/chat")
    async def chat(req: Request):
        body = await req.json()
        redacted, key = redact_body(body, mode="fast", lang="zh")
        llm_output = call_llm(redacted["text"])
        restored = restore_body({"result": llm_output}, key, field="result")
        return restored
"""

from __future__ import annotations

from argus_redact import redact, restore


def _validate_message(i: int, msg: object) -> None:
    """Raise TypeError if msg is not a valid chat message dict with a str content.

    Called per-element in the messages loop; centralises the three inline guards
    so the loop body stays focused on redaction logic.
    """
    if not isinstance(msg, dict):
        raise TypeError(
            f"redact_body: messages[{i}] is {type(msg).__name__}, not a dict; "
            f"each message must be a dict with a string 'content' key. "
            f"Bare-string message elements are not supported — nothing was redacted."
        )
    if "content" not in msg:
        raise TypeError(
            f"redact_body: messages[{i}] has no 'content' key "
            f"(keys present: {list(msg.keys())}); "
            f"tool/function-call messages and other non-content shapes are not "
            f"supported — nothing was redacted."
        )
    if not isinstance(msg["content"], str):
        raise TypeError(
            f"redact_body: messages[{i}]['content'] is "
            f"{type(msg['content']).__name__}, not str; "
            f"multimodal (list) content is not supported — nothing was redacted."
        )


def redact_body(
    body: dict,
    *,
    field: str = "text",
    mode: str = "fast",
    lang: str | list[str] = "zh",
    salt: int | bytes | None = None,
) -> tuple[dict, dict]:
    """Redact PII in a request body dict.

    Looks for `field` in body. If field is "messages", redacts each
    message's "content". Returns (redacted_body, key).
    """
    result = dict(body)
    combined_key: dict = {}

    if field == "messages" and "messages" in body:
        redacted_messages = []
        for i, msg in enumerate(body["messages"]):
            _validate_message(i, msg)
            new_msg = dict(msg)
            redacted_text, combined_key = redact(
                msg["content"],
                mode=mode,
                lang=lang,
                salt=salt,
                key=combined_key if combined_key else None,
            )
            new_msg["content"] = redacted_text
            redacted_messages.append(new_msg)
        result["messages"] = redacted_messages
    elif field in body:
        value = body[field]
        if not isinstance(value, str):
            # Fail CLOSED: a present-but-non-str field would otherwise be returned
            # un-redacted, silently leaking any PII inside the list/dict. Raise so
            # the caller fixes the field or uses redact_json() for nested shapes.
            raise TypeError(
                f"redact_body: body[{field!r}] is {type(value).__name__}, not str; "
                f"nothing was redacted. Pass a string field, or use redact_json() "
                f"for nested/list structures."
            )
        redacted_text, combined_key = redact(
            value,
            mode=mode,
            lang=lang,
            salt=salt,
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
        if isinstance(response[field], str):
            result[field] = restore(response[field], key)
        return result

    return response
