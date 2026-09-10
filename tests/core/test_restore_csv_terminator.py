"""`restore_csv` line-terminator behaviour.

Python's ``csv`` module normalizes line terminators onto its own writer
default (``\\r\\n``) on every reserialize, and ``_serialize_csv_rows`` strips
whatever trailing terminator the writer produced — so a restore can change a
file's line endings (and drop its trailing newline) even when not one cell
changed. An EMPTY key restores nothing at all, so round-tripping it through
``csv`` for that case is pure overhead that also corrupts the terminator; it
is skipped via a fast path that returns the input completely unchanged.
"""

from __future__ import annotations

from argus_redact.structured import restore_csv


class TestEmptyKeyFastPath:
    def test_restore_csv_should_be_identical_when_key_empty_and_crlf_has_trailing_newline(self):
        csv_text = "name,phone\r\n张三,13800138000\r\n"
        assert restore_csv(csv_text, {}) == csv_text

    def test_restore_csv_should_be_identical_when_key_empty_and_lf_has_trailing_newline(self):
        csv_text = "name,phone\n张三,13800138000\n"
        assert restore_csv(csv_text, {}) == csv_text

    def test_restore_csv_should_be_byte_identical_when_key_empty_with_no_trailing_newline(self):
        csv_text = "name,phone\n张三,13800138000"
        assert restore_csv(csv_text, {}) == csv_text

    def test_restore_csv_should_be_byte_identical_when_key_and_input_are_empty(self):
        assert restore_csv("", {}) == ""


class TestGeneralCaseDocumentedTerminatorNormalization:
    def test_restore_csv_should_normalize_to_crlf_and_drop_newline_when_key_non_empty(self):
        # Documented (not fixed) behaviour: a non-empty key takes the
        # parse/reserialize path, which writes CRLF regardless of the input's
        # own terminator and never re-adds a trailing one.
        key = {"P-1": "张三"}
        csv_text = "name,phone\nP-1,13800138000\n"
        restored = restore_csv(csv_text, key)
        assert restored == "name,phone\r\n张三,13800138000"
