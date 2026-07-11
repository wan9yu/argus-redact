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
