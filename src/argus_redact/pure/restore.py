"""restore(text, key) -> plaintext. Pure string replacement."""

from __future__ import annotations

import warnings
from typing import Mapping

from argus_redact.pure.display_marker import strip_display_markers


class RestoreGuardError(Exception):
    """Raised when guard=True, strict=True, and one or more security events occur."""

    def __init__(self, events: list[dict]) -> None:
        self.events = events
        codes = ", ".join(e["reason_code"] for e in events)
        super().__init__(f"restore guard failed: {codes}")


def check_restore_safety(
    redacted: str,
    llm_output: str,
    key: dict[str, str],
) -> list[str]:
    """Check if LLM output has suspicious pseudonym usage (possible injection).

    Returns a list of warning strings. Empty list = safe.
    Checks:
    1. Pseudonym frequency amplification (appears more than in original)
    2. Pseudonym near danger patterns (email, URL, exfiltration verbs)
    3. Reserved-range value amplification (realistic mode hallucinations)

    Delegated to the Rust core (``_core.check_restore_safety``).
    """
    from argus_redact._core import check_restore_safety as _rust_check

    return _rust_check(redacted, llm_output, key)


def wipe_key(key: dict) -> None:
    """Clear a key dict to minimize PII exposure in memory.

    Python strings are immutable and cannot be securely erased from memory,
    but clearing the dict removes references, allowing garbage collection sooner.
    For high-security scenarios, run argus-redact in a short-lived process.
    """
    key.clear()


def restore(
    text: str,
    key: Mapping[str, str],
    *,
    aliases: dict[str, tuple[str, ...]] | None = None,
    display_marker: str | None = None,
    guard: bool | None = None,
    anchor: object | None = None,
    strict: bool = False,
    detailed: bool = False,
) -> str | tuple[str, dict]:
    """Replace pseudonyms with originals using the key.

    `key` must be an in-memory mapping. The public
    ``argus_redact.restore(...)`` entry point also accepts a ``str`` path to a
    JSON key file; that file load happens in ``glue/restore.py`` (the I/O
    boundary) so this pure function stays filesystem-free.

    `aliases` (v0.6.0+): optional dict mapping a fake to alternate
    transliterations. Each alias is also matched and mapped back to the
    fake's original. Useful when the LLM rewrites Chinese names into pinyin
    or English addresses into 中文.

    If `display_marker` is provided, strip THAT marker from `text` before key
    lookup. If omitted, no separate marker pass runs: substitution is a single
    left-to-right, longest-key-first scan that advances past each replacement
    (never re-scanning what it just emitted). A decoration marker trailing a
    key token (`ⓕ`, `(假)`, `ˢ`, `*`) is ordinary non-key text, so it survives
    verbatim right after the restored value (e.g. `"19999123456ⓕ"` ->
    `"13800138000ⓕ"`). Pass `display_marker=` only when you want the marker
    removed from the output.

    Guard parameters (added v0.7.18, additive; the guard=None default flips to
    guard=True in v0.8.0):
        guard: when True, enables deterministic provenance (P) + scope (S) checks.
               when None (default), emits DeprecationWarning and runs legacy restore.
               when False, runs legacy restore (guard off) with NO warning — the
               explicit opt-out for callers that want a plain, unchecked restore.
        anchor: Anchor instance produced by make_anchor(); carries nonce + scope.
        strict: when True and guard=True, raises RestoreGuardError on any security event.
        detailed: when True, returns (result_text, {"security_events": [...]}) tuple.
    """
    if not isinstance(key, Mapping):
        raise TypeError(f"key must be a Mapping, got {type(key).__name__}")

    if guard is None:
        warnings.warn(
            "bare restore without guard= is deprecated; will default to guard=True in v0.8.0",
            DeprecationWarning,
            stacklevel=2,
        )
    if not guard:  # None (deprecated default) or False (explicit opt-out) → legacy restore
        result = _do_restore(text, key, aliases=aliases, display_marker=display_marker)
        if detailed:
            return result, {"security_events": []}
        return result

    # guard is True — run P + S checks
    from argus_redact.pure.security_events import (
        GUARD_NO_ANCHOR,
        OUT_OF_SCOPE_PSEUDONYM,
        PROVENANCE_FAILED,
        security_event,
    )

    events: list[dict] = []

    # (P) Provenance check: anchor must exist and its nonce must appear in text
    if anchor is None:
        events.append(security_event(GUARD_NO_ANCHOR, count=len(key), detail="no anchor provided"))
        return _fail_closed(text, events, strict=strict, detailed=detailed)

    if anchor.nonce not in text:
        events.append(
            security_event(PROVENANCE_FAILED, count=len(key), detail="nonce absent from response")
        )
        return _fail_closed(text, events, strict=strict, detailed=detailed)

    # (S) Scope filter: only restore pseudonyms within anchor.scope
    key_dict = dict(key) if not isinstance(key, dict) else key
    scoped = {k: v for k, v in key_dict.items() if k in anchor.scope}

    # Detect out-of-scope pseudonyms that appear in text
    out_of_scope_hits = [k for k in key_dict if k not in anchor.scope and k in text]
    if out_of_scope_hits:
        events.append(
            security_event(
                OUT_OF_SCOPE_PSEUDONYM,
                count=len(out_of_scope_hits),
                detail=f"withheld: {', '.join(sorted(out_of_scope_hits))}",
            )
        )

    # Restore only in-scope pseudonyms
    result = _do_restore(text, scoped, aliases=aliases, display_marker=display_marker)

    if strict and events:
        raise RestoreGuardError(events)

    if detailed:
        return result, {"security_events": events}
    return result


def _fail_closed(
    text: str,
    events: list[dict],
    *,
    strict: bool,
    detailed: bool,
) -> str | tuple[str, dict]:
    """Return un-restored text with security events; raise if strict."""
    if strict:
        raise RestoreGuardError(events)
    if detailed:
        return text, {"security_events": events}
    return text


def _do_restore(
    text: str,
    key: Mapping[str, str],
    *,
    aliases: dict[str, tuple[str, ...]] | None = None,
    display_marker: str | None = None,
) -> str:
    """Perform the actual substitution via Rust core."""
    if not key:
        if display_marker is not None:
            return strip_display_markers(text, marker=display_marker)
        return text

    if not isinstance(key, dict):
        key = dict(key)

    from argus_redact._core import restore as _rust_restore

    rust_aliases: dict[str, list[str]] | None = None
    if aliases:
        rust_aliases = {k: list(v) for k, v in aliases.items()}

    return _rust_restore(text, key, aliases=rust_aliases, display_marker=display_marker)
