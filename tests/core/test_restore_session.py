"""Tests for the PyO3 `StructuredRestorer` pyclass and its Python
`make_structured_restorer` helper.

`StructuredRestorer` wraps argus-redact-core's `RestoreSession`: a
stateful, unguarded restore session that precomputes the key/alias merge
and compiled regex once, then restores many cells against it. It mirrors
the existing `StructuredRedactor` session used for structured (CSV/JSON)
redaction, but for the restore side. Bulk callers (structured CSV/JSON,
streaming) route through it in later work; these tests pin the binding's
behavior directly.
"""

from __future__ import annotations

import re

import argus_redact._core as _core
import pytest

from argus_redact.pure.restore import make_structured_restorer, wipe_key

# Several (redacted_text, key) pairs covering: a single zh pseudonym, two
# distinct pseudonyms in one string, a key entry that never appears in the
# text (no-op for that entry), and a mixed zh/masked-value key.
REDACTED_KEY_PAIRS = [
    ("P-00001说话", {"P-00001": "张三"}),
    ("Hello P-1, meet P-2.", {"P-1": "Alice", "P-2": "Bob"}),
    ("no pseudonyms in this text", {"P-1": "Alice"}),
    ("P-1 phoned 138****8000", {"P-1": "王建国", "138****8000": "13800138000"}),
]


def test_structured_restorer_matches_core_restore():
    for text, key in REDACTED_KEY_PAIRS:
        restorer = _core.StructuredRestorer(key)
        expected_restored, _signals = _core.restore(text, key)

        assert restorer.restore_cell(text) == expected_restored


def test_wipe_key_does_not_invalidate_session():
    key = {"P-1": "王建国"}
    text = "P-1 phoned"
    restorer = make_structured_restorer(key)

    wipe_key(key)

    assert key == {}
    # The session holds its own copy — wiping the caller's dict must not
    # reach it.
    assert restorer.restore_cell(text) == "王建国 phoned"


def test_session_wipe_drops_state():
    key = {"P-1": "王建国"}
    text = "P-1 phoned"
    restorer = make_structured_restorer(key)

    restorer.wipe()

    assert restorer.restore_cell(text) == text


def test_make_structured_restorer_docstring_states_thread_safety():
    """`make_structured_restorer`'s docstring must warn that the returned
    `StructuredRestorer` session is single-thread/single-session — a
    concurrent `restore_cell` alongside `wipe()`/`close()` on a SHARED
    instance hits the underlying Rust runtime-borrow check and raises
    `Already borrowed`. Mirrors the single-session contract already
    documented on `StreamingRedactor` (`argus_redact.streaming`).
    """
    doc = make_structured_restorer.__doc__ or ""
    assert re.search(r"(?i)across threads", doc), (
        "make_structured_restorer docstring must warn against sharing the "
        "returned session across threads"
    )
    assert "Already borrowed" in doc, (
        "make_structured_restorer docstring must name the concrete failure "
        "mode (Already borrowed) a shared, concurrently-used session raises"
    )


class TestMakeStructuredRestorerAliasesValidation:
    """`make_structured_restorer` funnels `aliases` through the same
    `_normalize_aliases` seam `restore()` / `StreamingRestorer` use — a
    malformed shape must raise ValueError here too (restore_json/restore_csv
    reach this exact construction point)."""

    def test_rejects_bare_string_alias_value(self):
        with pytest.raises(ValueError):
            make_structured_restorer({"P-1": "Alice"}, aliases={"P-1": "abc"})

    def test_rejects_non_str_alias_element(self):
        with pytest.raises(ValueError):
            make_structured_restorer({"P-1": "Alice"}, aliases={"P-1": [123]})

    def test_accepts_tuple_valued_aliases(self):
        restorer = make_structured_restorer({"P-1": "Alice"}, aliases={"P-1": ("Al",)})
        assert restorer.restore_cell("Al ok") == "Alice ok"

    def test_none_and_empty_dict_are_equivalent(self):
        # Collapsing both onto the same Rust-constructor branch (aliases=None)
        # must not change observable behavior for either caller shape.
        none_restorer = make_structured_restorer({"P-1": "Alice"}, aliases=None)
        empty_restorer = make_structured_restorer({"P-1": "Alice"}, aliases={})
        text = "P-1 phoned"
        assert none_restorer.restore_cell(text) == empty_restorer.restore_cell(text)
