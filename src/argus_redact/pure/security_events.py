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


# Reason codes that mean the guard WITHHELD a substitution (fail-closed, or an
# out-of-scope code left as a placeholder). Everything else — notably the H
# heuristic's INJECTION_SUSPECTED — is ADVISORY: the restore proceeded and the
# originals WERE substituted. The two must never be described with one sentence:
# telling an operator investigating an injection that "pseudonyms were not
# substituted" when the plaintext was in fact handed back is worse than silence.
_WITHHELD_CODES = frozenset({PROVENANCE_FAILED, GUARD_NO_ANCHOR, OUT_OF_SCOPE_PSEUDONYM})


def warn_security_events(events: list[dict], *, stacklevel: int = 3) -> None:
    """Emit a PII-free SecurityWarning summarising ``events``.

    Structured ``security_events`` stay the channel for programs; this is the
    backstop for humans, so a caller on the default (non-detailed) path is never
    left with no signal at all. Carries reason_code + count ONLY — never
    ``detail``, which may hold raw text or pseudonyms — so it is safe for a log
    stream.

    The sentence describing what HAPPENED is derived from the reason codes, so it
    is accurate for withholding events, advisory ones, and a mix of both.
    """
    if not events:
        return
    import warnings

    from argus_redact.pure.replacer import SecurityWarning

    codes = [e["reason_code"] for e in events]
    withheld = any(c in _WITHHELD_CODES for c in codes)
    advisory = any(c not in _WITHHELD_CODES for c in codes)
    if withheld and advisory:
        outcome = (
            "some pseudonyms were NOT substituted; the remaining events are "
            "advisory and did not block the restore"
        )
    elif withheld:
        outcome = "affected pseudonyms were NOT substituted"
    else:
        outcome = "ADVISORY ONLY — the restore PROCEEDED and originals were substituted"

    summary = ", ".join(f"{e['reason_code']}x{e['count']}" for e in events)
    warnings.warn(
        f"restore security events ({summary}); {outcome} — "
        f"inspect detailed=True or use strict=True",
        SecurityWarning,
        stacklevel=stacklevel,
    )


def raise_if_strict(events: list[dict], strict: bool) -> None:
    """Raise RestoreGuardError when ``strict`` and any event fired.

    Shared by the integrations so the "advisory unless strict" policy is stated
    once rather than copy-pasted per wrapper.
    """
    if strict and events:
        from argus_redact.pure.restore import RestoreGuardError

        raise RestoreGuardError(events)
