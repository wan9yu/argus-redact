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


def test_guard_strict_raises():
    with pytest.raises(RestoreGuardError):
        restore("P-001", KEY, guard=True, strict=True)  # no anchor → raise


def test_bare_restore_deprecation_warning():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        restore("P-001", KEY)  # guard=None
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
    out, d = restore("P-001 138****5678", KEY, guard=False, detailed=True)
    assert "张三" in out  # guard did NOT run → restored
    assert d == {"security_events": []}
