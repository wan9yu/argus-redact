"""`restore_json` / `restore_csv` cell-collision hazard — document + pin.

`RestoreSession.restore_cell` (and the batch `restore_full` it mirrors)
substitutes any occurrence of a key's pseudonym code/mask/category-label
anywhere it appears in the text — it has no per-cell marker that says "this
specific span IS a placeholder `restore_json`/`restore_csv` just emitted", so
a BENIGN cell literal that happens to exactly equal one of the key's codes is
indistinguishable from a real placeholder and restores to that entity's
original. This is inherent to any placeholder-substitution scheme (a code
space collision), not a bug in the structured faces specifically — it exists
for the same reason `restore()`'s own docs call out "no false matches" as a
probabilistic property, not a guarantee.

These tests PIN the current, documented behaviour rather than assert a fix:
a coincidental literal match IS restored. See the "Known limitation" note
on `restore_json` / `restore_csv`.
"""

from __future__ import annotations

import inspect

from argus_redact.structured import restore_csv, restore_json


class TestBenignLiteralCollisionIsRestoredJSON:
    def test_a_cell_literal_equal_to_a_pseudonym_code_is_restored(self):
        key = {"P-00037": "王五"}
        data = {"literal_field": "P-00037", "unrelated": "hello"}

        restored = restore_json(data, key)

        assert restored["literal_field"] == "王五"
        assert restored["unrelated"] == "hello"


class TestBenignLiteralCollisionIsRestoredCSV:
    def test_a_cell_literal_equal_to_a_pseudonym_code_is_restored(self):
        key = {"P-00037": "王五"}
        csv_text = "code,note\nP-00037,literal not a real placeholder\n"

        restored = restore_csv(csv_text, key)

        rows = restored.splitlines()
        assert rows[1].startswith("王五,")


class TestDocstringDocumentsTheHazard:
    def test_restore_json_docstring_documents_the_collision_hazard(self):
        doc = (inspect.getdoc(restore_json) or "").lower()
        assert "coincidentally" in doc or "coincidental" in doc

    def test_restore_csv_docstring_documents_the_collision_hazard(self):
        doc = (inspect.getdoc(restore_csv) or "").lower()
        assert "coincidentally" in doc or "coincidental" in doc
