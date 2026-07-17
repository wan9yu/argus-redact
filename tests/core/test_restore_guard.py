import warnings

import pytest

from argus_redact.compose import make_anchor
from argus_redact.pure.restore import RestoreGuardError, restore

KEY = {"P-001": "张三", "138****5678": "13912345678"}


def _anchor_ok(text):
    a = make_anchor(KEY)
    return a, text + f"\n{a.nonce}"  # a genuine response echoes the nonce


def test_guard_provenance_ok_restores():
    a, resp = _anchor_ok("你好 P-001，号码 138****5678")
    out = restore(resp, KEY, guard=True, anchor=a)
    assert "张三" in out and "13912345678" in out


def test_guard_no_anchor_fail_closed():
    out, details = restore("P-001 138****5678", KEY, guard=True, detailed=True)
    assert "张三" not in out  # un-restored
    assert details["security_events"][0]["reason_code"] == "guard_no_anchor"


def test_guard_bad_nonce_fail_closed():
    a = make_anchor(KEY)
    out, d = restore("P-001 (no token)", KEY, guard=True, anchor=a, detailed=True)
    assert "张三" not in out
    assert d["security_events"][0]["reason_code"] == "provenance_failed"


def test_guard_out_of_scope_withheld_but_in_scope_restored():
    a = make_anchor({"P-001": "张三"})  # scope = {P-001} only
    resp = f"P-001 和 P-999 都在\n{a.nonce}"  # P-999 is out of scope
    key = {"P-001": "张三", "P-999": "王五"}
    out, d = restore(resp, key, guard=True, anchor=a, detailed=True)
    assert "张三" in out and "王五" not in out and "P-999" in out
    assert any(e["reason_code"] == "out_of_scope_pseudonym" for e in d["security_events"])


def test_out_of_scope_count_is_token_boundary_not_substring():
    # "P-1" is a substring of "P-10". The old substring check (`k in text`)
    # double-counted a single out-of-scope pseudonym in the response ("P-10")
    # as two hits, because "P-1" also matches as a substring of "P-10". This
    # is purely a reported-count bug — it never affects which pseudonyms get
    # withheld (that's the scope filter, unaffected here: P-1 is not in the
    # response at all).
    key = {"P-1": "Alice", "P-10": "Bob", "P-001": "张三"}
    a = make_anchor({"P-001": "张三"})  # scope = {P-001} only
    resp = f"P-001 和 P-10 都在\n{a.nonce}"
    out, d = restore(resp, key, guard=True, anchor=a, detailed=True)
    assert "Alice" not in out and "Bob" not in out and "张三" in out
    events = [e for e in d["security_events"] if e["reason_code"] == "out_of_scope_pseudonym"]
    assert len(events) == 1
    assert events[0]["count"] == 1


def test_guard_strict_raises():
    with pytest.raises(RestoreGuardError):
        restore("P-001", KEY, guard=True, strict=True)  # no anchor → raise


def test_bare_restore_deprecation_warning():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        restore("P-001", KEY, guard=None)  # v0.8.0: None must be explicit now
        assert any(issubclass(x.category, DeprecationWarning) for x in w)


def test_detailed_clean_call_returns_empty_events():
    a, resp = _anchor_ok("P-001 here")
    out, d = restore(resp, KEY, guard=True, anchor=a, detailed=True)
    assert d["security_events"] == []


def test_guard_false_restores_legacy():
    # guard=False is an explicit opt-out: plain legacy restore, no guard checks,
    # even with no anchor present (must NOT fail-closed).
    out = restore("P-001 138****5678", KEY, guard=False)
    assert "张三" in out and "13912345678" in out


def test_guard_false_no_deprecation_warning():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        restore("P-001", KEY, guard=False)
        assert not any(issubclass(x.category, DeprecationWarning) for x in w)


def test_guard_false_detailed_returns_empty_events():
    from argus_redact.pure.security_events import COMPLETE

    out, d = restore("P-001 138****5678", KEY, guard=False, detailed=True)
    assert "张三" in out  # guard did NOT run → restored
    # A legacy restore substitutes everything → outcome COMPLETE, no security events.
    # (The outcome key is now on every detailed return, so guarded_restore never has
    # to guess it from reason codes — see warn_security_events.)
    assert d == {"security_events": [], "outcome": COMPLETE}


def test_guard_empty_key_with_scope_advisory():
    # scope = {P-001} only, but the key handed to restore() has NOTHING in
    # that scope — the scoped filter empties out entirely and the restore is
    # a silent no-op reported COMPLETE unless this advisory event fires.
    a = make_anchor({"P-001": "张三"})
    key = {"P-999": "王五"}
    resp = f"P-999 在这里\n{a.nonce}"
    out, d = restore(resp, key, guard=True, anchor=a, detailed=True)
    assert "王五" not in out  # nothing was restored
    events = [e for e in d["security_events"] if e["reason_code"] == "empty_key_with_scope"]
    assert len(events) == 1
    assert events[0]["count"] == len(key)


def test_guard_normal_restore_no_empty_key_with_scope_event():
    # Control: scope covers the key and restoration actually happens — the
    # advisory above must NOT fire on the ordinary, successful path.
    a, resp = _anchor_ok("P-001 here")
    out, d = restore(resp, KEY, guard=True, anchor=a, detailed=True)
    assert "张三" in out
    assert not any(e["reason_code"] == "empty_key_with_scope" for e in d["security_events"])


def test_empty_string_key_entry_still_raises_not_advisory():
    # Control: a corrupted/hand-built key with an empty-string entry is a
    # distinct failure mode (restore-side rejection, Task 1) — it still
    # raises ValueError and must never be folded into this advisory event.
    with pytest.raises(ValueError, match="empty"):
        restore("abc", {"": "SECRET"}, guard=False)
