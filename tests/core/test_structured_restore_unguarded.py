"""Pin: structured restore (`restore_json` / `restore_csv`) is INTENTIONALLY
unguarded, and stays that way.

`RestoreSession` (the Rust session both faces share) hardcodes an empty
`events` list and `RestoreOutcome::Complete` over a full-key matcher with no
per-anchor scope — see `crates/argus-redact-core/src/restore.rs`. Threading a
per-anchor guard through it would require a new Rust return shape plus a
`structured.py` rewrite, not a parameter add, so it is a deliberate non-goal
(unlike the scalar `restore()` / `restore_guarded()` faces, which guard by
default since v0.8.0).

This is NOT a fail-closed assertion — the point is to PIN the current,
intentional shape so a future "just add guard=" edit to `restore_json` /
`restore_csv` is caught here instead of silently reshaping a stable public
signature.
"""

from __future__ import annotations

import inspect

from argus_redact.structured import restore_csv, restore_json


class TestNoGuardOrAnchorKeyword:
    def test_restore_json_accepts_no_guard_or_anchor_keyword(self):
        params = inspect.signature(restore_json).parameters
        assert "guard" not in params
        assert "anchor" not in params

    def test_restore_csv_accepts_no_guard_or_anchor_keyword(self):
        params = inspect.signature(restore_csv).parameters
        assert "guard" not in params
        assert "anchor" not in params


class TestDocstringStatesUnguarded:
    def test_restore_json_docstring_states_unguarded(self):
        doc = (inspect.getdoc(restore_json) or "").lower()
        assert "unguarded" in doc

    def test_restore_csv_docstring_states_unguarded(self):
        doc = (inspect.getdoc(restore_csv) or "").lower()
        assert "unguarded" in doc
