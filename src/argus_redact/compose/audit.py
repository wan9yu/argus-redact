"""compose.audit — compliance-as-artifact (Theme B, v0.7.18).

A caller-owned, append-only, PII-free, hash-chained AuditLedger that is BOTH the
audit trail and the tamper-evident record, plus collect_security_events to gather
the shared security_event schema from any redact/restore detailed result.
"""

from __future__ import annotations


def collect_security_events(result) -> list[dict]:
    """Extract PII-free security events uniformly. Handles a RedactReport
    (``.security_events``), a redact 3-tuple / restore 2-tuple (trailing details
    dict), or anything else (→ []). Tolerant by design."""
    if hasattr(result, "security_events"):
        return list(result.security_events)
    if isinstance(result, tuple) and result and isinstance(result[-1], dict):
        return list(result[-1].get("security_events", []))
    return []
