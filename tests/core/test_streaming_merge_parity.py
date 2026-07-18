"""Batch redact() and StreamingRedactor share the same entity merge.

``redact(mode="ner")`` and ``StreamingRedactor`` both funnel detected entities
through ``argus_redact.pure.merger.merge_entities`` (the Rust
``merge_entities_with_text`` core) before replacing them — batch calls it once
over the whole text, streaming calls it once over the retained buffer (via
``_context_cut``) and again after re-basing the surviving spans onto the emit
slice. Given the SAME detected entities, both must resolve an overlap the same
way. This pins that agreement for the fused-person case documented in
``tests/core/test_merge.py`` (``TestPersonCrossLayerMerge`` /
``TestKnownIssuesFusedNamePersonRepro``): an L1 candidate that fuses two names
into one span ("李明明王小丽") must be split into the two correct L2 spans by
both entry points, not just by whichever one is exercised directly.
"""

from unittest.mock import MagicMock, patch

from argus_redact import redact
from argus_redact._types import NEREntity
from argus_redact.impure.ner import NERAdapter
from argus_redact.streaming import StreamingRedactor

# Same repro text as tests/core/test_merge.py::TestKnownIssuesFusedNamePersonRepro
# — the L1 person candidate generator fuses "李明明" + "王小丽" into one 6-char
# span; only the L2 (NER) spans below name the correct boundary.
_TEXT = "客户李明明王小丽联系电话13800138000"
_SALT = 42


def _mock_ner_adapter() -> MagicMock:
    """Same NER mock shape as test_merge.py's fused-name repro."""
    adapter = MagicMock(spec=NERAdapter)
    adapter.detect.return_value = [
        NEREntity("李明明", "person", 2, 5, 0.95),
        NEREntity("王小丽", "person", 5, 8, 0.95),
    ]
    return adapter


def test_batch_and_streaming_agree_on_fused_person_merge():
    """Same NER mock, same text — batch and streaming must redact the same
    set of originals (with the same PII types), and neither may leak the
    fused wrong span or a trailing fragment of it.

    ``_get_ner_adapters`` is the single adapter-loading entry point both
    ``redact()`` and ``StreamingRedactor`` route through (the latter via
    ``_context_cut`` → ``_detect``), so one patch target covers both paths.
    """
    with patch(
        "argus_redact.glue.redact._get_ner_adapters",
        return_value=[_mock_ner_adapter()],
    ):
        redacted, batch_key, batch_types = redact(
            _TEXT, salt=_SALT, mode="ner", lang="zh", with_types=True
        )

    with patch(
        "argus_redact.glue.redact._get_ner_adapters",
        return_value=[_mock_ner_adapter()],
    ):
        redactor = StreamingRedactor(salt=_SALT, lang="zh", mode="ner")
        # Split the text mid fused-name span (after "王", before "小丽") across
        # two feed() calls — the buffer holds both until flush() drains it,
        # exercising the streaming re-entry path rather than a single detect.
        first_chunk, second_chunk = _TEXT[:6], _TEXT[6:]
        held = redactor.feed(first_chunk)
        assert held.downstream_text == "", "short text with no boundary must hold, not emit"
        redactor.feed(second_chunk)
        result = redactor.flush()

    # Neither path may leak the correct names, and neither may keep the L1
    # fused span (which would leak "小丽" as an unredacted trailing fragment).
    for text in (redacted, result.audit_text, result.downstream_text):
        assert "李明明" not in text
        assert "王小丽" not in text
        assert "小丽" not in text

    batch_originals_to_types = {original: batch_types[fake] for fake, original in batch_key.items()}
    stream_originals_to_types = {
        original: result.types[fake] for fake, original in result.key.items()
    }

    # The headline parity assertion: same originals, same types — i.e. the
    # merge resolved the L1/L2 overlap identically on both entry points.
    assert batch_originals_to_types == stream_originals_to_types
    assert batch_originals_to_types["李明明"] == "person"
    assert batch_originals_to_types["王小丽"] == "person"
