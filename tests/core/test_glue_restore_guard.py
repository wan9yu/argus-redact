"""Tests for guard kwargs threading through the public argus_redact.restore entry point.

Covers:
- guard=True + anchor works end-to-end via the public API
- str key-file path still loads and restores (backward-compat for key loading)
- no new kwargs → still returns a bare str (backward-compat for callers)
- detailed=True → returns (str, dict) via the public API
- strict=True + no anchor → raises via the public API
"""

import json
import warnings

import pytest

from argus_redact import restore
from argus_redact.compose import make_anchor
from argus_redact.pure.restore import RestoreGuardError

KEY = {"P-001": "张三", "138****5678": "13912345678"}


def _anchor_ok(text: str):
    """Create a valid anchor and append its nonce to text."""
    a = make_anchor(KEY)
    return a, text + f"\n{a.nonce}"


class TestGlueGuardPassthrough:
    """guard kwargs thread from the public entry through glue to pure."""

    def test_guard_true_anchor_restores_via_public_api(self):
        """guard=True + valid anchor → originals restored, nonce present."""
        a, resp = _anchor_ok("你好 P-001，号码 138****5678")
        out = restore(resp, KEY, guard=True, anchor=a)
        assert "张三" in out
        assert "13912345678" in out

    def test_guard_true_no_anchor_fail_closed_via_public_api(self):
        """guard=True, no anchor → fail-closed (un-restored text), no exception."""
        out, details = restore("P-001 138****5678", KEY, guard=True, detailed=True)
        assert "张三" not in out
        assert details["security_events"][0]["reason_code"] == "guard_no_anchor"

    def test_guard_true_strict_raises_via_public_api(self):
        """guard=True + strict=True + no anchor → RestoreGuardError raised."""
        with pytest.raises(RestoreGuardError):
            restore("P-001", KEY, guard=True, strict=True)

    def test_detailed_true_returns_tuple_via_public_api(self):
        """detailed=True → (str, dict) even on a clean call."""
        a, resp = _anchor_ok("P-001 here")
        result = restore(resp, KEY, guard=True, anchor=a, detailed=True)
        assert isinstance(result, tuple)
        text_out, info = result
        assert "张三" in text_out
        assert info["security_events"] == []


class TestGlueKeyFilePathBackcompat:
    """str key-file path still loads and restores correctly."""

    def test_str_path_key_loads_and_restores(self, tmp_path):
        """A str path to a JSON key file is resolved at the glue boundary."""
        key_file = tmp_path / "key.json"
        key_file.write_text(json.dumps(KEY))
        # Use legacy bare restore (no guard kwarg) to keep this pure path test
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            out = restore("P-001 来了", str(key_file))
        assert "张三" in out

    def test_str_path_key_with_guard_kwargs(self, tmp_path):
        """str path + guard kwargs: file loads, then guard logic runs."""
        key_file = tmp_path / "key.json"
        key_file.write_text(json.dumps(KEY))
        a, resp = _anchor_ok("P-001 说话")
        out = restore(resp, str(key_file), guard=True, anchor=a)
        assert "张三" in out


class TestGlueBackwardCompat:
    """No new kwargs → still returns a bare str (backward compatibility)."""

    def test_no_guard_kwargs_returns_str(self):
        """Calling restore without any new kwargs still returns a bare str."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            result = restore("P-001 来了", KEY)
        assert isinstance(result, str)
        assert "张三" in result

    def test_no_guard_kwargs_emits_deprecation_warning(self):
        """Calling restore without guard= still emits DeprecationWarning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            restore("P-001", KEY)
        assert any(issubclass(x.category, DeprecationWarning) for x in w)
