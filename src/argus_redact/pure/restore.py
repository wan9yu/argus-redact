"""restore(text, key) -> plaintext. Pure string replacement."""

from __future__ import annotations

import logging
import warnings
from typing import Mapping

from argus_redact.exceptions import SecurityWarning
from argus_redact.pure.replacer import alias_collision_event, warn_alias_collisions
from argus_redact.pure.security_events import (
    ALIAS_COLLISION,
    BLOCKED,
    COMPLETE,
    EMPTY_KEY_WITH_SCOPE,
    GUARD_NO_ANCHOR,
    OUT_OF_SCOPE_PSEUDONYM,
    PARTIAL,
    PROVENANCE_FAILED,
    _auto_stacklevel,
    security_event,
    warn_security_events,
)

logger = logging.getLogger(__name__)


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


# Maps `_core.restore_guarded`'s `outcome` string onto the same BLOCKED/
# PARTIAL/COMPLETE constants every other outcome-producing call site
# (`_fail_closed`, the legacy branch above) uses — so `warn_security_events`
# and `detailed=True` see one consistent vocabulary no matter which path
# produced it. An explicit KeyError on an unrecognised value (rather than a
# silent fallback) is deliberate: a future core outcome this shim does not yet
# render must fail loudly, not mislabel the restore.
_CORE_OUTCOME = {"blocked": BLOCKED, "partial": PARTIAL, "complete": COMPLETE}


def _event_from_core(event: dict) -> dict:
    """Rebuild one Python ``security_event`` dict from a core guard event.

    ``event`` is one of `_core.restore_guarded`'s structured
    ``{"kind": str, "count": int, "tokens": list[str] | None}`` records — the
    core decides WHICH check fired and how big/which tokens it carries, but
    carries zero prose (see ``GuardEvent`` in the Rust ``restore.rs``). This is
    the one place that turns ``kind`` back into the Python reason_code
    constant and builds the (PII-free) ``detail`` string that
    ``detailed=True`` and the docs describe, so callers can never see it
    rendered two different ways.

    ``guard_no_anchor`` never reaches here: core only ever runs from
    ``restore()`` once a real anchor exists, so that event is built directly
    in Python, in the ``anchor is None`` branch above.
    """
    kind, count = event["kind"], event["count"]
    if kind == PROVENANCE_FAILED:
        return security_event(PROVENANCE_FAILED, count=count, detail="nonce absent from response")
    if kind == EMPTY_KEY_WITH_SCOPE:
        return security_event(
            EMPTY_KEY_WITH_SCOPE,
            count=count,
            detail="anchor.scope excluded every key entry; nothing was restored",
        )
    if kind == OUT_OF_SCOPE_PSEUDONYM:
        # Mirrors the ALIAS_COLLISION branch below: names how many were withheld,
        # never the tokens themselves — see "injection_suspected and
        # out_of_scope_pseudonym report counts, not specifics" in
        # docs/known-issues.md. A caller that needs the specific codes already
        # holds everything needed to derive them: `set(key) - set(anchor.scope)`.
        return security_event(
            OUT_OF_SCOPE_PSEUDONYM,
            count=count,
            detail=f"{count} pseudonym(s) withheld: outside this anchor's scope",
        )
    if kind == ALIAS_COLLISION:
        # Mirrors `alias_collision_event`: names how many collided, never the raw
        # alias/original strings (`count` is already the distinct-alias count core
        # dedups to, matching Python's `set()` semantics).
        return security_event(ALIAS_COLLISION, count=count, detail=f"{count} alias(es) collided")
    raise ValueError(f"unrecognised guard event kind from core: {kind!r}")


def wipe_key(key: dict) -> None:
    """Clear a key dict to minimize PII exposure in memory.

    Python strings are immutable and cannot be securely erased from memory,
    but clearing the dict removes references, allowing garbage collection sooner.
    For high-security scenarios, run argus-redact in a short-lived process.

    This only clears the CALLER's dict — it has no effect on a
    `make_structured_restorer` session, which took its own copy of `key` at
    construction. A session manages its own lifetime via its own `wipe()` /
    `close()` methods.
    """
    key.clear()


def make_structured_restorer(
    key: dict[str, str],
    *,
    aliases: dict[str, tuple[str, ...]] | None = None,
):
    """Build a stateful `_core.StructuredRestorer` session for restoring many
    cells (structured CSV/JSON, streaming) against the same key.

    The session precomputes the key/alias merge and compiled regex once at
    construction, then reuses them across every `restore_cell` call — mirrors
    `pure.replacer.make_structured_session` on the redact side.

    `aliases` mirrors the batch `restore(text, key, aliases=...)` parameter —
    alternate transliterations that map back to the same original. The core
    session has always accepted them; threading them here is what lets the
    streaming face reach the same restore coverage as the batch face.

    `dict(...)` is deliberate: the session gets its OWN copy, so a later
    `wipe_key(key)` on the caller's dict cannot reach the session's copy.
    Wipe the session itself via its `wipe()` / `close()` methods.
    """
    from argus_redact import _core

    if aliases is None:
        return _core.StructuredRestorer(dict(key))
    return _core.StructuredRestorer(dict(key), {k: list(v) for k, v in aliases.items()})


def restore(
    text: str,
    key: Mapping[str, str],
    *,
    aliases: dict[str, tuple[str, ...]] | None = None,
    display_marker: str | None = None,
    guard: bool | None = True,
    anchor: object | None = None,
    strict: bool = False,
    detailed: bool = False,
    _warn: bool = True,
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

    Guard parameters (added v0.7.18; the default flipped to guard=True in v0.8.0):
        guard: when True (default, v0.8.0+), enables deterministic provenance (P) +
               scope (S) checks. A bare restore(text, key) with no anchor now FAILS
               CLOSED — the text is returned un-restored.
               when None, emits a DeprecationWarning and runs the legacy (unguarded)
               restore; if it actually substitutes at least one pseudonym it ALSO
               emits a SecurityWarning naming the consequence (R4) — the caller has
               not yet chosen, so the risk is surfaced.
               when False, runs the legacy restore (guard off) with NO warning at
               all — the explicit, informed opt-out for callers that want a plain,
               unchecked restore.
        anchor: Anchor instance produced by make_anchor(); carries nonce + scope.
        strict: when True and guard=True, raises RestoreGuardError on any security event.
        detailed: when True, returns (result_text, {"security_events": [...]}) tuple.

    ``_warn`` is internal: False suppresses the SecurityWarning for this call, for a
    wrapper that will surface the same events itself (``glue.guarded_restore`` merges
    them with its own H events and warns ONCE over the merged list). It never
    suppresses the ``guard=None`` DeprecationWarning — that one is about the CALLER's
    code and no wrapper re-emits it.
    """
    if not isinstance(text, str):
        # The Rust boundary rejects a non-str, but only on paths that reach it:
        # the guard's fail-closed no-anchor branch returns before any core call,
        # so a dict/list/int came straight back out as the "restored" value.
        # Check up front so every branch and every face fails the same way.
        raise TypeError(f"text must be a string, got {type(text).__name__}")
    if not isinstance(key, Mapping):
        raise TypeError(f"key must be a Mapping, got {type(key).__name__}")

    if guard is None:
        # Auto-detect the caller's frame, same as the security warnings. A
        # deprecation warning exists to tell the user WHERE to change their code;
        # a hardcoded stacklevel pointed it at argus's own glue/restore.py, which
        # defeats the entire purpose (and collapses a whole loop of bare restores
        # into one warning via warnings' (message, module, lineno) dedup).
        warnings.warn(
            "guard=None runs the legacy unguarded restore and is deprecated; the guard is "
            "the default as of v0.8.0 — pass guard=True with an anchor for a guarded restore, "
            "or guard=False for an explicit unguarded one",
            DeprecationWarning,
            stacklevel=_auto_stacklevel(),
        )
    if not guard:  # None (deprecated) or False (explicit opt-out) → legacy restore
        alias_collisions: list[str] = []
        result = _do_restore(
            text,
            key,
            aliases=aliases,
            display_marker=display_marker,
            _warn=_warn,
            _alias_collisions=alias_collisions,
        )
        # R4: make the unguarded-restore consequence visible in production. Only the
        # None path warns — the caller has NOT chosen, and originals were reinserted
        # with no injection check. guard=False is the informed opt-out (the warning
        # text itself points there), so it stays silent. Fires only when a pseudonym
        # was actually substituted (result changed), so a no-op restore is quiet.
        if guard is None and _warn and key and result != text:
            warnings.warn(
                "restore ran WITHOUT the provenance/scope guard; originals were "
                "reinserted with no injection check — pass guard=True with an anchor, "
                "or guard=False if you intend an unguarded restore",
                SecurityWarning,
                stacklevel=_auto_stacklevel(),
            )
        if detailed:
            # A legacy restore substitutes every pseudonym (no scope filter), so the
            # outcome is COMPLETE. Emitting it here means guarded_restore never sees a
            # None outcome from an internal caller, so warn_security_events never falls
            # back to guessing from reason codes (see its docstring).
            legacy_events: list[dict] = []
            _ac_event = alias_collision_event(alias_collisions)
            if _ac_event:
                legacy_events.append(_ac_event)
            return result, {"security_events": legacy_events, "outcome": COMPLETE}
        return result

    # guard is True — the P (provenance) + S (scope) DECISION lives in the Rust
    # core (`_core.restore_guarded`); this branch's job is only to (a) keep the
    # anchor-less case in Python (core never sees it), (b) hand the anchor'd
    # case to core, and (c) reconstruct the human-readable event strings from
    # core's structured, prose-free `{kind, count, tokens}` output — Python
    # owns every string a caller can see, core owns zero of them.
    events: list[dict] = []

    # (P) Provenance check: anchor must exist at all. `_core.restore_guarded` is
    # only ever called below, with a real nonce, so this fail-closed case never
    # reaches core.
    if anchor is None:
        events.append(security_event(GUARD_NO_ANCHOR, count=len(key), detail="no anchor provided"))
        return _fail_closed(text, events, strict=strict, detailed=detailed, warn=_warn)

    from argus_redact._core import restore_guarded as _rust_restore_guarded

    rust_aliases: dict[str, list[str]] | None = None
    if aliases:
        rust_aliases = {k: list(v) for k, v in aliases.items()}

    # `_core.restore_guarded`'s own docstring flags this as a policy call for
    # the Python shim, not the binding: a bare Python `None` for `nonce` means
    # "no anchor at all" to the binding (it skips building an Anchor and takes
    # the always-complete unguarded path) — but here `anchor` IS present, just
    # with a degenerate (non-str) nonce, e.g. `Anchor(nonce=None, ...)`. That
    # must still fail closed as a provenance failure, not slip through as
    # unguarded-complete. Coerce any non-str nonce to "" — a string core's own
    # length-floor check (`MIN_NONCE_LEN`, in the core's restore module) rejects
    # exactly like a missing one, so the Anchor is still built and provenance
    # still fails.
    nonce = anchor.nonce if isinstance(anchor.nonce, str) else ""

    # `_alias_collisions` (the raw, undeduped list) is discarded here: core's own
    # `alias_collision` guard event already carries the deduped count/tokens this
    # branch needs, so there is nothing left for the raw list to drive.
    result, _alias_collisions, core_events, core_outcome = _rust_restore_guarded(
        text,
        dict(key),
        aliases=rust_aliases,
        display_marker=display_marker,
        nonce=nonce,
        scope=list(anchor.scope),
    )
    events.extend(_event_from_core(event) for event in core_events)

    # A blocked outcome is, by construction, a provenance failure — the ONLY
    # fail-closed the core produces (EmptyKeyWithScope/OutOfScopePseudonym yield
    # complete/partial, never blocked). Route it through `_fail_closed` exactly
    # as the pre-refactor nonce-mismatch branch did, so it keeps that path's
    # per-occurrence ops-channel `logger.warning` (which `warn_security_events`
    # alone does NOT emit) alongside the same SecurityWarning. `result` is core's
    # raw un-restored text on a block, so the returned shape is identical, and
    # `_fail_closed` also owns the strict-raise for this case.
    if core_outcome == BLOCKED:
        return _fail_closed(result, events, strict=strict, detailed=detailed, warn=_warn)

    if strict and events:
        raise RestoreGuardError(events)

    outcome = _CORE_OUTCOME[core_outcome]

    if events and _warn:
        # Partial restore: in-scope codes were substituted, out-of-scope ones were
        # withheld. Without this the caller gets a plain str and no hint that some
        # pseudonyms were deliberately left unresolved.
        # stacklevel auto-detected — see security_events._auto_stacklevel.
        warn_security_events(events, outcome)

    if detailed:
        return result, {"security_events": events, "outcome": outcome}
    return result


def _fail_closed(
    text: str,
    events: list[dict],
    *,
    strict: bool,
    detailed: bool,
    warn: bool = True,
) -> str | tuple[str, dict]:
    """Return un-restored text with security events; warn; raise if strict."""
    if strict:
        raise RestoreGuardError(events)
    # The returned str is shape-identical to a successful restore, so without this
    # the caller cannot tell a fail-closed apart from a clean round-trip. Documented
    # in docs/security-model.md ("emits a UserWarning") — this is that warning.
    # stacklevel auto-detected — see security_events._auto_stacklevel.
    # This function only ever runs on a TOTAL fail-closed (no anchor, or nonce
    # mismatch) — nothing is EVER substituted here, so the outcome is always
    # BLOCKED, never PARTIAL/COMPLETE.
    if warn:
        warn_security_events(events, BLOCKED)
    # Ops channel: warnings dedup per (message, module, lineno), so a loop of
    # fail-closed restores collapses to one visible warning. logging has no such
    # per-callsite dedup, so an operator watching the log stream sees every
    # fail-closed. PII-free — reason codes + counts only, never `detail`.
    logger.warning(
        "restore fail-closed: %s",
        ", ".join(f"{e['reason_code']}x{e['count']}" for e in events),
    )
    if detailed:
        return text, {"security_events": events, "outcome": BLOCKED}
    return text


def _do_restore(
    text: str,
    key: Mapping[str, str],
    *,
    aliases: dict[str, tuple[str, ...]] | None = None,
    display_marker: str | None = None,
    _warn: bool = True,
    _alias_collisions: list[str] | None = None,
) -> str:
    """Perform the actual substitution via Rust core.

    ``_warn``: False suppresses the ``alias_collision`` SecurityWarning for
    this call — the same suppression contract ``restore()``'s own ``_warn``
    documents, threaded through so a caller that asked for silence (or that
    folds the collision into its own combined warning, see the guarded branch
    of ``restore()``) actually gets it.

    ``_alias_collisions``, if given, is MUTATED in place: the Rust core's
    authoritative alias-collision list is extended onto it, so a caller
    building a ``detailed=True`` ``security_events`` list can turn it into an
    ``alias_collision`` event via ``alias_collision_event`` — mirrors the
    ``_mask_collisions`` out-param idiom in
    ``glue.redact._do_replace_and_persist``.
    """
    if not key:
        # An empty key means no fakes were ever marked, so there is nothing
        # to strip. Do NOT globally strip display_marker here — that would
        # destroy unrelated occurrences (e.g. markdown `**bold**`).
        return text

    if not isinstance(key, dict):
        key = dict(key)

    from argus_redact._core import restore as _rust_restore

    rust_aliases: dict[str, list[str]] | None = None
    if aliases:
        rust_aliases = {k: list(v) for k, v in aliases.items()}

    result, signals = _rust_restore(text, key, aliases=rust_aliases, display_marker=display_marker)
    alias_collisions = signals["alias_collisions"]
    if _alias_collisions is not None:
        _alias_collisions.extend(alias_collisions)
    if _warn:
        warn_alias_collisions(alias_collisions)
    return result
