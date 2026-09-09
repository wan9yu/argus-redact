"""Input-validation gaps in the structured (JSON/CSV) faces.

Two entry-guards ``redact()`` already enforces had no equivalent here:

- an invalid ``mode`` (a typo, e.g. ``"bogus"``) passed straight through to
  detection instead of being rejected up front — including on an EMPTY input,
  where the early return skipped validation entirely.
- an empty or degenerate ``paths=`` selector (``[]``, ``[""]``, ``["."]``,
  ``[[]]``, ``[[""]]``) either silently redacted the WHOLE document (the
  opposite of what a caller scoping to a subtree asked for), silently matched
  nothing, or crashed with a raw ``AttributeError``/``TypeError`` deep inside
  the walk instead of a clean, typed error at the entry point. ``[[""]]`` is
  the list-form counterpart of the string-form ``[""]``: the two selector
  spellings must agree on being rejected.

``paths=None`` (the whole-document default) must keep working exactly as
before — only the new degenerate/malformed cases are rejected.
"""

import pytest

from argus_redact import redact_csv, redact_json


def test_redact_json_rejects_invalid_mode():
    with pytest.raises(ValueError, match="mode"):
        redact_json({"a": "13812345678"}, mode="bogus", salt=b"0" * 32)


def test_redact_csv_rejects_invalid_mode_on_empty_input():
    # The empty-input path returns early, before any per-cell detection ever
    # runs — mode must still be validated even though there is nothing to redact.
    with pytest.raises(ValueError, match="mode"):
        redact_csv("", mode="bogus", salt=b"0" * 32)


def test_redact_csv_rejects_invalid_mode_on_nonempty_input():
    with pytest.raises(ValueError, match="mode"):
        redact_csv("phone\n13812345678\n", mode="bogus", salt=b"0" * 32)


@pytest.mark.parametrize("bad", [[], [""], ["."], [[]], [[""]]])
def test_empty_selector_rejected(bad):
    with pytest.raises(ValueError):
        redact_json({"a": "13812345678"}, paths=bad, salt=b"0" * 32)


@pytest.mark.parametrize("bad", [[("user", "phone")], [["user", 1]]])
def test_nonstr_selector_rejected(bad):
    with pytest.raises(TypeError):
        redact_json({"a": "13812345678"}, paths=bad, salt=b"0" * 32)


def test_paths_none_still_whole_document():
    out, _key = redact_json({"a": "13812345678"}, paths=None, salt=b"0" * 32)
    assert out["a"] != "13812345678"  # whole-doc default unchanged


def test_paths_scoped_selector_still_leaves_other_leaves_untouched():
    # A valid, non-degenerate selector's behavior must be byte-identical to
    # before this change: scoped leaves redact, everything outside stays put.
    data = {"user": {"phone": "13812345678"}, "other": "13800001111"}
    out, _key = redact_json(data, paths=["user.phone"], salt=b"0" * 32)
    assert out["user"]["phone"] != "13812345678"
    assert out["other"] == "13800001111"
