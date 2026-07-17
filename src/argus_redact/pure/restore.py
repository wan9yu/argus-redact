"""restore(text, key) -> plaintext. Pure string replacement."""

from __future__ import annotations

import logging
import re
import warnings
from typing import Mapping

from argus_redact.exceptions import SecurityWarning
from argus_redact.pure.replacer import alias_collision_event, warn_alias_collisions
from argus_redact.pure.security_events import (
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


# A make_anchor nonce is secrets.token_hex(16) = 32 chars. A floor well below
# that (real nonces pass) but far above any incidental text-suffix collision
# rejects short degenerate nonces as provenance proofs. The coupling to
# make_anchor's token length is enforced by test_make_anchor_nonce_clears_floor
# so the producer can't shrink its token below what this consumer accepts.
_MIN_NONCE_LEN = 16


def _nonce_echoed(text: str, nonce: object) -> bool:
    """True only if the model echoed ``nonce`` as instructed — as a whole token,
    on its own line or as the trailing token (the shape ``prompt_anchor`` asks for
    and ``_strip_nonce`` removes).

    Provenance means the model reproduced OUR verification token, not that the
    token happens to appear somewhere in the reply. A bare ``nonce in text`` test
    accepted three degenerate nonces that are not proofs at all: an empty nonce
    (a substring of everything), a nonce that is an incidental substring of the
    text (a common character), and — via ``in`` on a non-str — ``None`` (a
    TypeError). All three must read as "not echoed" so the guard fails closed
    instead of trusting the anchor and letting ``_strip_nonce`` destroy or corrupt
    the caller's text. A genuine ``make_anchor`` nonce (32 hex chars on its own
    line) satisfies this; nothing incidental does.
    """
    # Reject sub-token-length nonces before the shape check (rationale on
    # _MIN_NONCE_LEN): a short string can incidentally be a text suffix and pass
    # `endswith`, and an empty/None one is never a proof.
    if not isinstance(nonce, str) or len(nonce) < _MIN_NONCE_LEN:
        return False
    if text.rstrip().endswith(nonce):  # documented trailing echo
        return True
    return any(line.strip() == nonce for line in text.split("\n"))  # own-line echo


def _strip_nonce(text: str, nonce: str) -> str:
    """Remove the echoed verification token from the model's reply.

    ``prompt_anchor`` instructs the model to end its reply with the token **on its
    own line** (see ``compose/anchor.py`` ``_NONCE_ECHO_*`` — if that wording ever
    changes, this stripper must change with it). Without this the token, which is
    not a pseudonym and so is invisible to the substitution pass, would be handed
    back to the caller as part of the restored plaintext.

    The documented shape (token last) is handled in one pass; the fallbacks cover a
    model that puts it on its own line mid-reply or echoes it inline.
    """
    if not isinstance(nonce, str) or len(nonce) < _MIN_NONCE_LEN:
        # Defense in depth: a degenerate nonce has no valid echo to strip, and
        # stripping it WOULD destroy or corrupt the text (an empty nonce slices the
        # whole string away). The only caller gates on _nonce_echoed first, so this
        # never fires today — but a function whose failure mode is "silently destroy
        # the caller's plaintext" must refuse degenerate input regardless of caller.
        return text
    trimmed = text.rstrip()
    if trimmed.endswith(nonce):  # the documented case — no full-text rebuild needed
        return trimmed[: -len(nonce)].rstrip()
    kept = [line for line in text.split("\n") if line.strip() != nonce]
    out = "\n".join(kept)
    if nonce in out:  # defensive: echoed inline rather than on its own line
        out = out.replace(nonce, "")
    return out.rstrip()


def _tokens_present(pseudonyms: list[str], text: str) -> list[str]:
    """The ``pseudonyms`` that appear in ``text`` as whole tokens (sorted).

    A match must not be merely a substring of a longer pseudonym-shaped run
    (e.g. ``P-1`` embedded in ``P-10``). Generated pseudonyms are
    ``<PREFIX>-<digits>`` runs of letters, digits, underscores and hyphens, so
    plain ``\\b`` word boundaries are not enough — a hyphen is not a word
    character, but must still not count as a boundary between two
    pseudonym-shaped tokens.

    ONE alternation scan over the whole set, longest-first (so ``P-10`` wins
    over ``P-1`` at the same offset), rather than a full-text scan per
    pseudonym: the per-key version was O(keys x len(text)) and dominated the
    guarded path on realistic key sizes.

    Used only to size the ``out_of_scope_pseudonym`` security event's ``count``
    and ``detail``; it never changes which pseudonyms are withheld (that is
    structural, driven by the scoped key filter in ``restore``, not by this
    check).
    """
    if not pseudonyms:
        return []
    alternation = "|".join(re.escape(p) for p in sorted(pseudonyms, key=len, reverse=True))
    pattern = re.compile(r"(?<![A-Za-z0-9_-])(?:" + alternation + r")(?![A-Za-z0-9_-])")
    return sorted(set(pattern.findall(text)))


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

    # guard is True — run P + S checks
    events: list[dict] = []

    # (P) Provenance check: anchor must exist and its nonce must appear in text
    if anchor is None:
        events.append(security_event(GUARD_NO_ANCHOR, count=len(key), detail="no anchor provided"))
        return _fail_closed(text, events, strict=strict, detailed=detailed, warn=_warn)

    if not _nonce_echoed(text, anchor.nonce):
        events.append(
            security_event(PROVENANCE_FAILED, count=len(key), detail="nonce absent from response")
        )
        return _fail_closed(text, events, strict=strict, detailed=detailed, warn=_warn)

    # Provenance holds. The token has done its job — strip it so it never reaches
    # the caller as part of the restored plaintext (it is not a pseudonym, so the
    # substitution pass below would otherwise carry it straight through).
    text = _strip_nonce(text, anchor.nonce)

    # (S) Scope filter: only restore pseudonyms within anchor.scope
    key_dict = dict(key) if not isinstance(key, dict) else key
    scoped = {k: v for k, v in key_dict.items() if k in anchor.scope}

    # Advisory: the key was non-empty and anchor.scope is non-empty, but scope
    # excluded EVERY entry — the restore below is a silent no-op that would
    # otherwise be reported COMPLETE with no hint that nothing was substituted.
    # Distinct from the corruption empty-string-key case (that raises); this is
    # a legitimate, non-overlapping scope and key, so it only advises, never blocks.
    if key_dict and not scoped and anchor.scope:
        events.append(
            security_event(
                EMPTY_KEY_WITH_SCOPE,
                count=len(key_dict),
                detail="anchor.scope excluded every key entry; nothing was restored",
            )
        )

    # Detect out-of-scope pseudonyms that appear in text — see `_tokens_present`.
    # Cosmetic only: it sizes the event's `count`/`detail`, never which pseudonyms
    # get withheld (that is `scoped` above).
    out_of_scope_hits = _tokens_present([k for k in key_dict if k not in anchor.scope], text)
    if out_of_scope_hits:
        events.append(
            security_event(
                OUT_OF_SCOPE_PSEUDONYM,
                count=len(out_of_scope_hits),
                detail=f"withheld: {', '.join(out_of_scope_hits)}",  # already sorted
            )
        )

    # Restore only in-scope pseudonyms
    alias_collisions: list[str] = []
    result = _do_restore(
        text,
        scoped,
        aliases=aliases,
        display_marker=display_marker,
        # _warn=False here (never the direct warning) is deliberate: the
        # collision is folded into `events` below instead, so it rides the ONE
        # combined `warn_security_events` call further down — the same
        # SecurityWarning P + S events already share. Warning here too would
        # double-fire (once specific-text, once generic) for the same event.
        _warn=False,
        _alias_collisions=alias_collisions,
    )
    if alias_collisions:
        _ac_event = alias_collision_event(alias_collisions)
        if _ac_event:
            events.append(_ac_event)

    if strict and events:
        raise RestoreGuardError(events)

    # out_of_scope_hits means some pseudonyms present in the text were outside
    # this call's scope and withheld (PARTIAL — the restore was limited to scope);
    # no hits means nothing in the text was withheld (COMPLETE — any events left
    # are advisory, e.g. from guarded_restore's H layer merged in later). PARTIAL
    # does not itself witness whether any in-scope pseudonym was actually present
    # or substituted, so the warning must not claim it was.
    outcome = PARTIAL if out_of_scope_hits else COMPLETE

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

    result, alias_collisions = _rust_restore(
        text, key, aliases=rust_aliases, display_marker=display_marker
    )
    if _alias_collisions is not None:
        _alias_collisions.extend(alias_collisions)
    if _warn:
        warn_alias_collisions(alias_collisions)
    return result
