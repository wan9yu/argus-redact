"""``redact(_pre_detected=...)`` must validate the caller-supplied spans.

Unlike ``_detect``'s Rust-produced entities, a ``_pre_detected`` list (the
integration point ``StreamingRedactor``, the Presidio bridge, and
``redact_pseudonym_llm`` all route through) is caller-supplied and builds the
pure-Python ``_types.PatternMatch`` directly — no PyO3 ``usize`` wrapper stands
between a malformed span and the splice. A negative offset or an inverted
``(start, end)`` pair used to reach the splice unchecked: either it fails open
(the replacement lands on the wrong slice, potentially skipping the PII the
caller meant to redact) or it corrupts the output.

An ``end`` past the end of the text is a DIFFERENT, legitimate case (e.g. a
caller passing a whole-line span without measuring its exact length) and must
keep working exactly as before: Rust ``assemble_splice`` clamps it at splice
time, and ``report=True`` still echoes the ORIGINAL (unclamped) span in
``entity_details`` — this is not a bug to fix, and this file pins it as a
regression guard.
"""

import pytest

from argus_redact import redact
from argus_redact._types import PatternMatch


def _pm(start, end):
    return PatternMatch(text="x", type="phone", start=start, end=end, confidence=1.0, layer=1)


@pytest.mark.parametrize("start,end", [(5, 3), (-1, 3)])
def test_reject_invalid_span(start, end):
    with pytest.raises(ValueError):
        redact("hello 13812345678", _pre_detected=[_pm(start, end)], salt=b"0" * 32)


def test_out_of_range_end_still_clamps_whole_doc():
    out = redact("hello", _pre_detected=[_pm(0, 999)], salt=b"0" * 32, report=True)
    assert out.entities[0]["end"] == 999  # entity_details echoes the ORIGINAL span
    assert out.redacted_text != "hello"  # the whole (clamped) document was redacted
