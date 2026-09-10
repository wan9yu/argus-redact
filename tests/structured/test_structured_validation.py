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


def test_redact_json_should_reject_invalid_mode():
    with pytest.raises(ValueError, match="mode"):
        redact_json({"a": "13812345678"}, mode="bogus", salt=b"0" * 32)


def test_redact_csv_should_reject_invalid_mode_when_input_is_empty():
    # The empty-input path returns early, before any per-cell detection ever
    # runs — mode must still be validated even though there is nothing to redact.
    with pytest.raises(ValueError, match="mode"):
        redact_csv("", mode="bogus", salt=b"0" * 32)


def test_redact_csv_should_reject_invalid_mode_when_input_is_nonempty():
    with pytest.raises(ValueError, match="mode"):
        redact_csv("phone\n13812345678\n", mode="bogus", salt=b"0" * 32)


@pytest.mark.parametrize("bad", [[], [""], ["."], [[]], [[""]]])
def test_redact_json_should_reject_an_empty_selector(bad):
    with pytest.raises(ValueError):
        redact_json({"a": "13812345678"}, paths=bad, salt=b"0" * 32)


@pytest.mark.parametrize("bad", [[("user", "phone")], [["user", 1]]])
def test_redact_json_should_reject_a_nonstring_selector(bad):
    with pytest.raises(TypeError):
        redact_json({"a": "13812345678"}, paths=bad, salt=b"0" * 32)


def test_redact_json_should_redact_the_whole_document_when_paths_is_none():
    out, _key = redact_json({"a": "13812345678"}, paths=None, salt=b"0" * 32)
    assert out["a"] != "13812345678"  # whole-doc default unchanged


def test_redact_json_should_leave_other_leaves_untouched_when_paths_scopes_a_selector():
    # A valid, non-degenerate selector's behavior must be byte-identical to
    # before this change: scoped leaves redact, everything outside stays put.
    data = {"user": {"phone": "13812345678"}, "other": "13800001111"}
    out, _key = redact_json(data, paths=["user.phone"], salt=b"0" * 32)
    assert out["user"]["phone"] != "13812345678"
    assert out["other"] == "13800001111"
