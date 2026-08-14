"""guarded_restore() — the complete guarded-restore flow, in one place.

The flow is: supplementary heuristic (H) → fail closed if strict → the deterministic
guard (P + S) inside restore() → merge the events → surface them → return.

It lives here, once, because copy-pasting it is what produced D1 (v0.7.19): three of
our own five integrations had it wrong — one dropped the events it had just computed,
one could not reach `strict` at all, and one performed no H check whatsoever. Every
integration now calls this; so should yours.

H stays ADVISORY by default. It is a heuristic, and a heuristic is never promoted to
the deterministic guarantee — that is P + S. `strict=True` is the opt-in that makes a
suspected injection fail closed.

`key` may be a str path to a key file. The glue `restore()` normally resolves that
path itself, but the H check (`check_restore_safety`) needs a resolved dict too — so
the path is resolved ONCE here, at the top, and the same dict is handed to both the H
check and the restore call. This keeps H working for key-file callers instead of
silently skipping it for a whole class of caller.

Having resolved the key, we then call `pure.restore.restore` DIRECTLY rather than the
glue `restore()`: the only thing the glue layer adds is that key-file load, which is
already done by the time we get here. Going direct also keeps the internal `_warn`
opt-out (below) off the frozen Layer-1 public signature, where it does not belong.
"""

from __future__ import annotations

from argus_redact.glue.restore import _load_key_file
from argus_redact.pure.restore import check_restore_safety
from argus_redact.pure.restore import restore as _restore
from argus_redact.pure.security_events import (
    INJECTION_SUSPECTED,
    raise_if_strict,
    security_event,
    warn_security_events,
)


def guarded_restore(
    text: str,
    key: dict[str, str] | str,
    *,
    aliases: dict[str, tuple[str, ...]] | None = None,
    display_marker: str | None = None,
    redacted: str | None = None,
    anchor: object | None = None,
    guard: bool | None = True,
    strict: bool = False,
    detailed: bool = False,
    warn: bool | None = None,
) -> "str | tuple[str, dict]":
    """Restore pseudonyms with the full guard flow.

    Args:
        text: the model's reply, containing pseudonyms.
        key: the key dict from redact(), or a str path to a key file.
        aliases: optional {fake: (alternate, ...)} from redact(); each alternate
            is also mapped back to the fake's original. Without it a
            cross-language alias form the model emitted (张三 -> "Zhang San")
            silently fails to restore on this recommended guarded path.
        display_marker: optional decoration marker to strip from `text` before
            key lookup. Both are forwarded verbatim into the core restore.
        redacted: the redacted prompt. Supply it to enable the supplementary
            injection heuristic (H); without it, no H check runs.
        anchor: the Anchor from make_anchor(key). Required for the guard to pass.
        guard: True (default) runs the deterministic provenance + scope checks.
        strict: raise RestoreGuardError instead of returning — covers BOTH the
            deterministic guard and a suspected injection. Opt-in fail-closed.
        detailed: return (text, {"security_events": [...]}) instead of just text.
        warn: whether to emit the SecurityWarning. None (default) means "warn iff
            NOT detailed" — a detailed caller reads the structured events, a plain
            caller would otherwise get no signal at all. Pass True alongside
            detailed=True when a caller needs BOTH (the MCP tool serialises the
            events into its JSON payload AND wants the human-facing warning).
            Surfacing is decided HERE, never re-implemented by an integration —
            that split ownership is what produced D1.
    """
    key_dict = _load_key_file(key) if isinstance(key, str) else key

    h_events: list[dict] = []
    if redacted is not None and key_dict:
        hints = check_restore_safety(redacted, text, key_dict)
        if hints:
            # Count only, never the specifics — see "injection_suspected and
            # out_of_scope_pseudonym report counts, not specifics" in
            # docs/known-issues.md for why the pseudonym code and proximity-check
            # match are both unsafe to carry here. `len(hints)` is (pseudonym x
            # finding) pairs across all three check_restore_safety checks, so
            # "pattern(s)" would mislabel two of the three.
            h_events.append(
                security_event(
                    INJECTION_SUSPECTED,
                    count=len(hints),
                    detail=f"{len(hints)} suspicious finding(s) from the injection "
                    "heuristic; specifics available via check_restore_safety",
                )
            )

    # Fail closed BEFORE restoring, so on a suspected injection no original is ever
    # substituted — not even into a local we then throw away.
    raise_if_strict(h_events, strict)

    # _warn=False: restore() would otherwise warn about its own (P/S) events from a
    # DIFFERENT, disjoint event list than h_events above. Warning twice — once per
    # list — makes warn_security_events' mixed (withheld + advisory) branch
    # unreachable, and worse: on a fail-closed P/S trip plus an advisory H hit, the
    # second warning FALSELY claimed the restore proceeded when nothing was in fact
    # substituted (see the _WITHHELD_CODES comment in pure/security_events.py). Its
    # events come back through detailed=True instead and are folded into ONE combined
    # warning below. _warn=False does NOT suppress the guard=None DeprecationWarning,
    # which is about the caller's own code and propagates untouched.
    result_text, details = _restore(
        text,
        key_dict,
        aliases=aliases,
        display_marker=display_marker,
        guard=guard,
        anchor=anchor,
        strict=strict,
        detailed=True,
        _warn=False,
    )

    all_events = h_events + details.get("security_events", [])
    # `restore()` is the site that witnessed whether P + S actually let anything
    # through — BLOCKED (fail-closed), PARTIAL (scope withheld some), or COMPLETE
    # (everything in scope substituted). Forward that as-is rather than
    # re-deriving it from the merged reason codes, which is exactly the bug this
    # replaces: a BLOCKED restore plus an advisory H hit must still say BLOCKED,
    # not a mixed sentence implying some of it went through.
    outcome = details.get("outcome")

    if warn is None:
        warn = not detailed
    if warn:
        # ONE warning over the merged events, using the outcome witnessed above —
        # never dropped, never re-guessed from reason codes.
        warn_security_events(all_events, outcome)

    if detailed:
        return result_text, {"security_events": all_events, "outcome": outcome}
    return result_text
