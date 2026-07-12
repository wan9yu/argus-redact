"""
Internal security event schema and reason codes — shared by the guard-restore
flow (Theme A) and redact-side compliance events (Theme B, keep_downgraded).

Not exported via __all__; internal use only.
"""

from __future__ import annotations

import os
import sys
import warnings

from argus_redact.exceptions import SecurityWarning

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

# The argus_redact package directory, derived from this file's location
# (.../src/argus_redact/pure/security_events.py -> .../src/argus_redact). Used
# to tell "library internals" apart from "the caller's own code" when walking
# the stack — see `_auto_stacklevel` below. The trailing separator prevents a
# sibling directory with a matching prefix (e.g. `argus_redact_extra`) from
# being mistaken for a frame inside this package.
_PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__))) + os.sep


def _auto_stacklevel(default: int = 3) -> int:
    """Compute the ``warnings.warn`` ``stacklevel`` that attributes to the
    caller's OWN code, no matter how many argus_redact wrappers sit between it
    and ``warn_security_events`` (a direct ``restore()``, a fail-closed
    ``restore()`` one frame deeper via ``_fail_closed``, a call through
    ``glue.restore``, through ``guarded_restore``, through an integration, or
    through any wrapper added later).

    Hardcoding a single number tuned to one call shape is exactly the bug this
    replaces: every new layer of wrapping needs its own magic number, and one
    number cannot serve every shape at once. Walking the stack for the first
    frame outside the package is correct for all of them, by construction.

    ``stacklevel=1`` is the frame containing the ``warnings.warn(...)`` call
    itself — i.e. inside ``warn_security_events``. Each frame further out is
    one more. This function is called FROM ``warn_security_events``, so
    ``sys._getframe(n)`` here lands on exactly the frame that ``stacklevel=n``
    would attribute to: frame 1 is ``warn_security_events``'s own frame, frame
    2 is its caller, and so on. We start the walk at frame 2 (the caller) and
    step outward until a frame's source file is not inside the package.
    """
    level = 2
    try:
        frame = sys._getframe(level)
    except ValueError:
        # Stack too shallow to even reach warn_security_events's caller — can
        # happen in tests that call this helper in isolation. Don't crash the
        # warning path over an attribution nicety.
        return default
    while frame is not None:
        filename = os.path.realpath(frame.f_code.co_filename)
        if not filename.startswith(_PACKAGE_DIR):
            return level
        frame = frame.f_back
        level += 1
    # Ran off the top of the stack without leaving the package (e.g. a test
    # harness that calls internal functions directly with no external caller
    # in the chain). Fall back rather than pointing at a nonexistent frame.
    return default


def warn_security_events(events: list[dict], *, stacklevel: int | None = None) -> None:
    """Emit a PII-free SecurityWarning summarising ``events``.

    Structured ``security_events`` stay the channel for programs; this is the
    backstop for humans, so a caller on the default (non-detailed) path is never
    left with no signal at all. Carries reason_code + count ONLY — never
    ``detail``, which may hold raw text or pseudonyms — so it is safe for a log
    stream.

    The sentence describing what HAPPENED is derived from the reason codes, so it
    is accurate for withholding events, advisory ones, and a mix of both.

    ``stacklevel``: ``None`` (the default) auto-detects the first frame outside
    the argus_redact package and attributes the warning there — see
    ``_auto_stacklevel``. Pass an explicit int to override, e.g. for a caller
    that knows its own depth is unusual; it is used verbatim, no auto-detection.
    """
    if not events:
        return

    if stacklevel is None:
        stacklevel = _auto_stacklevel()

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


def advisory_events(events: list[dict]) -> list[dict]:
    """Return the ``events`` that are ADVISORY — i.e. NOT in ``_WITHHELD_CODES``.

    Everything that isn't a withholding code (P/S failures, out-of-scope
    pseudonyms) is advisory, currently just the H heuristic's
    ``INJECTION_SUSPECTED``. For a caller that already warns about its own P/S
    events through some other path and only needs to separately surface the
    advisory ones (avoiding a double-report of the same P/S trip), derive the
    set from this helper rather than naming a reason code directly — naming
    one is exactly the drift that let a future advisory code go unsurfaced
    silently. ``guarded_restore`` and its integrations no longer need this
    split themselves (they warn once over the full merged list — see
    ``glue/guarded_restore.py``); it remains for any caller with its own,
    separate P/S warning path.
    """
    return [e for e in events if e["reason_code"] not in _WITHHELD_CODES]


def raise_if_strict(events: list[dict], strict: bool) -> None:
    """Raise RestoreGuardError when ``strict`` and any event fired.

    Shared by the integrations so the "advisory unless strict" policy is stated
    once rather than copy-pasted per wrapper.
    """
    if strict and events:
        from argus_redact.pure.restore import RestoreGuardError

        raise RestoreGuardError(events)
