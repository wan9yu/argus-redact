"""redact_csv must not corrupt non-PII cell whitespace.

The serialized CSV was returned via ``.strip()``, which deletes leading whitespace
from the very first cell (and any trailing whitespace in the last cell) — silent,
unrecoverable corruption of data the redactor was never asked to touch. Only the
csv.writer's trailing line terminator should be trimmed.
"""

from argus_redact.structured import redact_csv


def test_leading_whitespace_of_first_cell_is_preserved():
    text = "  indent,plainval\r\nrow2a,row2b"
    redacted, _key = redact_csv(text, has_header=False, mode="fast", lang="zh", salt=42)
    # The two leading spaces of cell (0,0) are non-PII and must survive.
    assert redacted.startswith("  indent"), redacted
    # Re-parsing the output yields the same rows (modulo redaction — none here).
    import csv
    import io

    rows = list(csv.reader(io.StringIO(redacted)))
    assert rows == [["  indent", "plainval"], ["row2a", "row2b"]]


def test_interior_whitespace_cells_unaffected():
    text = "x, ,y\r\np,q,r"
    redacted, _key = redact_csv(text, has_header=False, mode="fast", lang="zh", salt=42)
    import csv
    import io

    rows = list(csv.reader(io.StringIO(redacted)))
    assert rows == [["x", " ", "y"], ["p", "q", "r"]]


def test_no_trailing_blank_line_from_writer():
    # The csv.writer appends \r\n; that (and only that) should be trimmed.
    text = "a,b\r\nc,d"
    redacted, _key = redact_csv(text, has_header=False, mode="fast", lang="zh", salt=42)
    assert not redacted.endswith("\r\n")
    assert not redacted.endswith("\n")
