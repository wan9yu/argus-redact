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
    def test_crlf_input_with_trailing_newline_is_byte_identical(self):
        csv_text = "name,phone\r\n张三,13800138000\r\n"
        assert restore_csv(csv_text, {}) == csv_text

    def test_lf_input_with_trailing_newline_is_byte_identical(self):
        csv_text = "name,phone\n张三,13800138000\n"
        assert restore_csv(csv_text, {}) == csv_text

    def test_no_trailing_newline_input_is_byte_identical(self):
        csv_text = "name,phone\n张三,13800138000"
        assert restore_csv(csv_text, {}) == csv_text

    def test_empty_string_input_is_byte_identical(self):
        assert restore_csv("", {}) == ""


class TestGeneralCaseDocumentedTerminatorNormalization:
    def test_non_empty_key_normalizes_lf_to_crlf_and_drops_trailing_newline(self):
        # Documented (not fixed) behaviour: a non-empty key takes the
        # parse/reserialize path, which writes CRLF regardless of the input's
        # own terminator and never re-adds a trailing one.
        key = {"P-1": "张三"}
        csv_text = "name,phone\nP-1,13800138000\n"
        restored = restore_csv(csv_text, key)
        assert restored == "name,phone\r\n张三,13800138000"
