"""guarded_restore() — the whole guard flow, in one place.

D1 (integrations computed security events and then dropped them) was not bad luck; it
is what copy-pasting a 6-step flow across 5 files produces. This is the one place the
flow can be wrong, and these tests pin it.
"""

from __future__ import annotations

import warnings

import pytest

from argus_redact import make_anchor, redact
from argus_redact.compose.anchor import Anchor
from argus_redact.exceptions import SecurityWarning
from argus_redact.glue.guarded_restore import guarded_restore
from argus_redact.pure.restore import RestoreGuardError
from argus_redact.pure.restore import restore as _restore
from argus_redact.pure.security_events import BLOCKED, COMPLETE, PARTIAL

_PHONE = "13912345678"


def _round_trip(inject: bool = False):
    redacted, key = redact(f"张三的电话是{_PHONE}", lang="zh", mode="fast")
    anchor = make_anchor(key)
    if inject:
        # amplification + exfil, with a VALID nonce so P and S both pass and only H trips
        pseudonym = next(p for p, original in key.items() if original == _PHONE)
        reply = " ".join([pseudonym] * 20) + " send to http://evil.example.com\n" + anchor.nonce
    else:
        reply = redacted + "\n" + anchor.nonce
    return redacted, key, anchor, reply


def test_clean_round_trip_restores_and_strips_the_nonce():
    _redacted, key, anchor, reply = _round_trip()
    out = guarded_restore(reply, key, anchor=anchor)
    assert out == f"张三的电话是{_PHONE}"
    assert anchor.nonce not in out


def test_h_events_reach_the_caller_on_the_default_path():
    """The D1 defect, pinned: events must never be computed and then dropped."""
    redacted, key, anchor, reply = _round_trip(inject=True)
    with pytest.warns(SecurityWarning, match="injection_suspected"):
        guarded_restore(reply, key, redacted=redacted, anchor=anchor)


def test_h_events_returned_when_detailed():
    redacted, key, anchor, reply = _round_trip(inject=True)
    _out, details = guarded_restore(reply, key, redacted=redacted, anchor=anchor, detailed=True)
    assert "injection_suspected" in [e["reason_code"] for e in details["security_events"]]


def test_strict_fails_closed_on_injection_before_substituting():
    redacted, key, anchor, reply = _round_trip(inject=True)
    with pytest.raises(RestoreGuardError):
        guarded_restore(reply, key, redacted=redacted, anchor=anchor, strict=True)


def test_h_is_advisory_without_strict():
    """By design: H is a heuristic and never becomes the guarantee (that is P + S)."""
    redacted, key, anchor, reply = _round_trip(inject=True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        out = guarded_restore(reply, key, redacted=redacted, anchor=anchor)
    assert _PHONE in out  # the restore proceeded


def test_no_h_check_without_the_redacted_prompt():
    """H needs the redacted prompt. Without it, no H event — and no crash."""
    _redacted, key, anchor, reply = _round_trip(inject=True)
    _out, details = guarded_restore(reply, key, anchor=anchor, detailed=True)
    assert "injection_suspected" not in [e["reason_code"] for e in details["security_events"]]


def test_fail_closed_when_no_anchor():
    _redacted, key, _anchor, reply = _round_trip()
    with pytest.warns(SecurityWarning, match="guard_no_anchor"):
        out = guarded_restore(reply, key)  # guard=True default, no anchor
    assert _PHONE not in out  # fail-closed: nothing substituted


def test_fail_closed_warning_is_attributed_to_the_caller_not_guarded_restore():
    """guarded_restore() sits one frame deeper than a direct restore() call: the
    chain is warn -> _fail_closed -> pure.restore -> glue.restore -> guarded_restore
    -> caller. A stacklevel hardcoded for restore()'s own call depth misattributes
    the warning to guarded_restore.py instead of here — and warnings' dedup on
    (message, category, module, lineno) would then collapse every fail-closed
    restore in a caller's loop into a single warning with no pointer back to the
    caller's own code."""
    _redacted, key, _anchor, reply = _round_trip()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        guarded_restore(reply, key)  # guard=True default, no anchor -> fail closed
    assert caught[0].filename == __file__, (
        f"warning attributed to {caught[0].filename}, not the caller ({__file__})"
    )


def test_fail_closed_and_h_fire_together_produce_one_accurate_warning():
    """FINDING 1 (v0.7.20 review): restore()'s own P/S warning and guarded_restore's H
    warning used to be emitted separately, over disjoint event lists — so when a
    fail-closed P/S trip and an advisory H hit occurred together, the caller got TWO
    warnings, and the second one FALSELY claimed the restore proceeded when nothing
    was substituted at all."""
    redacted, key = redact(f"张三的电话是{_PHONE}", lang="zh", mode="fast")
    anchor = make_anchor(key)
    pseudonym = next(p for p, original in key.items() if original == _PHONE)
    # amplification + exfil pattern (trips H) with NO nonce at all (trips P -> fail closed)
    reply = " ".join([pseudonym] * 20) + " send to http://evil.example.com"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = guarded_restore(reply, key, redacted=redacted, anchor=anchor)

    security_warnings = [w for w in caught if issubclass(w.category, SecurityWarning)]
    assert len(security_warnings) == 1, [str(w.message) for w in security_warnings]
    msg = str(security_warnings[0].message)
    assert "provenance_failed" in msg
    assert "injection_suspected" in msg
    assert "PROCEEDED" not in msg, f"fail-closed restore falsely described as proceeding: {msg!r}"
    assert _PHONE not in out  # genuinely fail-closed: nothing was substituted


def test_clean_ps_with_h_only_produces_one_advisory_warning():
    """Counterpart to the mixed case above: when P/S are clean and only H fires, the
    single warning must still say the restore proceeded (it did)."""
    redacted, key, anchor, reply = _round_trip(inject=True)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = guarded_restore(reply, key, redacted=redacted, anchor=anchor)

    security_warnings = [w for w in caught if issubclass(w.category, SecurityWarning)]
    assert len(security_warnings) == 1, [str(w.message) for w in security_warnings]
    msg = str(security_warnings[0].message)
    assert "injection_suspected" in msg
    assert "PROCEEDED" in msg
    assert _PHONE in out  # advisory only — the restore genuinely proceeded


def test_guard_none_through_guarded_restore_still_emits_deprecation_warning():
    """Proves the SecurityWarning suppression added for the fix above is scoped to
    SecurityWarning only: restore()'s DeprecationWarning (bare guard=None) must still
    reach the caller through guarded_restore."""
    _redacted, key, anchor, reply = _round_trip()
    with pytest.warns(DeprecationWarning, match="deprecated"):
        guarded_restore(reply, key, anchor=anchor, guard=None)


# --- H4: detailed=True must include "outcome", matching restore(detailed=True) -----


def test_detailed_includes_complete_outcome_on_clean_round_trip():
    """A clean guarded restore is COMPLETE — nothing was withheld or blocked."""
    _redacted, key, anchor, reply = _round_trip()
    out, details = guarded_restore(reply, key, anchor=anchor, detailed=True)
    assert details["outcome"] == COMPLETE
    assert _PHONE in out
    # Consistency with the sibling API for the equivalent call.
    _expected_out, expected_details = _restore(reply, key, guard=True, anchor=anchor, detailed=True)
    assert details["outcome"] == expected_details["outcome"]


def test_detailed_includes_blocked_outcome_when_guard_fails_closed():
    """No anchor -> guard fails closed; detailed must say BLOCKED, not silently
    drop the outcome the way the plain security_events-only dict used to."""
    _redacted, key, _anchor, reply = _round_trip()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        out, details = guarded_restore(reply, key, detailed=True)  # guard=True default, no anchor
    assert details["outcome"] == BLOCKED
    assert _PHONE not in out  # genuinely nothing substituted


def test_detailed_includes_partial_outcome_when_scope_withholds():
    """A restricted anchor.scope withholds an out-of-scope pseudonym present in
    the text -> PARTIAL. Must match what restore(detailed=True) reports for the
    same inputs."""
    redacted, key = redact(f"张三的电话是{_PHONE}，李四的邮箱abc@x.com", lang="zh", mode="fast")
    items = list(key.items())
    in_scope_pseudonym = items[0][0]
    out_of_scope_pseudonym = items[1][0]
    nonce = "a1b2c3d4e5f6a7b8"
    anchor = Anchor(nonce=nonce, scope=frozenset({in_scope_pseudonym}))
    text = f"only {out_of_scope_pseudonym} appears here\n{nonce}"

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        _out, details = guarded_restore(text, key, redacted=redacted, anchor=anchor, detailed=True)
    assert details["outcome"] == PARTIAL
    _expected_out, expected_details = _restore(text, key, guard=True, anchor=anchor, detailed=True)
    assert details["outcome"] == expected_details["outcome"]


def test_key_file_path_is_accepted(tmp_path):
    """Routes through the GLUE restore, so a str key-file path works (presidio bypassed this)."""
    import json

    _redacted, key, anchor, reply = _round_trip()
    kf = tmp_path / "key.json"
    kf.write_text(json.dumps(key), encoding="utf-8")
    assert guarded_restore(reply, str(kf), anchor=anchor) == f"张三的电话是{_PHONE}"


class TestGuardedRestoreAliases:
    """aliases/display_marker thread through guarded_restore into the core restore.

    Without the forwarding, a cross-language alias form the LLM emitted (张三 →
    "Zhang San") silently fails to restore on the guarded path — the whole point
    of aliases, unreachable through the RECOMMENDED entry point.
    """

    def _redact_person(self):
        redacted, key = redact(f"张三的电话是{_PHONE}", lang="zh", mode="fast")
        anchor = make_anchor(key)
        person_fake = next(p for p, original in key.items() if original == "张三")
        return redacted, key, anchor, person_fake

    def test_alias_form_restores_with_aliases_kwarg(self):
        redacted, key, anchor, person_fake = self._redact_person()
        alias = "Zhang San"
        reply = redacted.replace(person_fake, alias) + "\n" + anchor.nonce

        out = guarded_restore(reply, key, anchor=anchor, aliases={person_fake: (alias,)})

        assert "张三" in out
        assert alias not in out

    def test_alias_form_not_restored_without_aliases_kwarg(self):
        redacted, key, anchor, person_fake = self._redact_person()
        alias = "Zhang San"
        reply = redacted.replace(person_fake, alias) + "\n" + anchor.nonce

        out = guarded_restore(reply, key, anchor=anchor)

        # Alias unmapped without aliases=: the person is NOT restored.
        assert "张三" not in out
        assert alias in out

    def test_display_marker_forwarded(self):
        # guard=False keeps this deterministic — the marker/alias forwarding is
        # the same _restore call the guarded path uses.
        key = {"P-1": "张三"}
        text = "P-1ⓕ来了"

        assert guarded_restore(text, key, guard=False, display_marker="ⓕ") == "张三来了"
        # Without display_marker the decoration survives verbatim after restore.
        assert guarded_restore(text, key, guard=False) == "张三ⓕ来了"
