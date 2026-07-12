"""
Internal security event schema and reason codes — shared by the guard-restore
flow (Theme A) and redact-side compliance events (Theme B, keep_downgraded).

Not exported via __all__; internal use only.
"""

PROVENANCE_FAILED = "provenance_failed"
OUT_OF_SCOPE_PSEUDONYM = "out_of_scope_pseudonym"
INJECTION_SUSPECTED = "injection_suspected"
GUARD_NO_ANCHOR = "guard_no_anchor"
KEEP_DOWNGRADED = "keep_downgraded"


def security_event(reason_code: str, count: int, detail: str | None = None) -> dict:
    """
    Build a security event record.

    Args:
        reason_code: One of the PROVENANCE_FAILED, OUT_OF_SCOPE_PSEUDONYM,
                     INJECTION_SUSPECTED, GUARD_NO_ANCHOR, KEEP_DOWNGRADED
                     constants.
        count: Number of PII items affected by this event.
        detail: Optional context about the event (e.g., "nonce absent").

    Returns:
        dict with type, reason_code, count, detail.
    """
    return {"type": "security", "reason_code": reason_code, "count": count, "detail": detail}


def warn_security_events(events: list[dict], *, stacklevel: int = 3) -> None:
    """Emit a PII-free SecurityWarning summarising ``events``.

    Structured ``security_events`` stay the channel for programs; this is the
    backstop for humans, so a caller on the default (non-detailed) path is never
    left with no signal at all. Carries reason_code + count ONLY — never
    ``detail``, which may hold raw text or pseudonyms — so it is safe for a log
    stream.
    """
    if not events:
        return
    import warnings

    from argus_redact.pure.replacer import SecurityWarning

    summary = ", ".join(f"{e['reason_code']}x{e['count']}" for e in events)
    warnings.warn(
        f"restore security events ({summary}); affected pseudonyms were NOT "
        f"substituted — inspect detailed=True or use strict=True",
        SecurityWarning,
        stacklevel=stacklevel,
    )
