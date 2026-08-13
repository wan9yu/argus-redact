"""Streaming pollution guard must fire on a reserved-range value split across chunks.

The eager per-chunk ``_check_input_pollution`` in ``StreamingRedactor.feed`` is a
WHOLE-TOKEN regex, so a reserved-range value split across feed-chunk boundaries
(real streaming deltas are token-sized) matches neither half. The real guard is
the emit-time scan inside ``redact_pseudonym_llm``, which runs over the
REASSEMBLED emit slice (``buffer[ctx:cut]``) where a cross-chunk-split token is
whole again. These tests pin that both feed() and flush() route through it, and
that the eager fast path, the ``strict_input=False`` opt-out, and clean streams
are all preserved.
"""

import pytest

from argus_redact import PseudonymPollutionError
from argus_redact.pure.restore import restore
from argus_redact.streaming import StreamingRedactor


class TestSplitReservedValueRaises:
    def test_reserved_phone_split_across_two_chunks_raises(self):
        # 19999123456 is a reserved-range fake phone; splitting it across the
        # chunk boundary hides it from the eager whole-token check, but the
        # reassembled emit slice at flush sees it whole.
        r = StreamingRedactor(salt=42, lang="zh")
        r.feed("用户张伟的电话是1999912")
        r.feed("3456，请处理。")
        with pytest.raises(PseudonymPollutionError):
            r.flush()

    def test_reserved_phone_fed_one_char_at_a_time_raises(self):
        # Char-by-char is the strongest proof that the REASSEMBLED-buffer scan
        # (not the per-chunk check) is what fires: no single feed carries more
        # than one digit of the reserved value.
        r = StreamingRedactor(salt=42, lang="zh")
        with pytest.raises(PseudonymPollutionError):
            for ch in "用户张伟的电话是19999441813，请处理。":
                r.feed(ch)
            r.flush()

    def test_reserved_phone_split_reassembles_only_at_flush_raises(self):
        # Each chunk carries only a fragment of the reserved phone, so the eager
        # check misses every one; the value becomes whole only in the flushed
        # tail — the flush() path must still catch it.
        r = StreamingRedactor(salt=42, lang="zh")
        r.feed("用户张伟的电话是199991")
        r.feed("23456")
        r.feed("。")
        with pytest.raises(PseudonymPollutionError):
            r.flush()

    def test_reserved_split_emitted_mid_stream_by_feed_raises(self):
        # A split reserved value followed by >W (128) chars of clean forward
        # context is emitted by feed() itself (not held for flush), exercising
        # the feed() emit path through the same emit-time scan.
        r = StreamingRedactor(salt=42, lang="zh")
        r.feed("电话是1999912")
        r.feed("3456。")
        with pytest.raises(PseudonymPollutionError):
            # Long clean forward context pushes the reserved sentence past the
            # context-cut boundary so feed() emits (and scans) it.
            r.feed("接下来是一段很长的说明文字。" * 20)


class TestGuardDoesNotOverfire:
    def test_clean_stream_token_by_token_redacts_without_raising(self):
        # The buffer holds INPUT only (never argus's own reserved-range fakes),
        # so the emit-time scan cannot spuriously raise on the fake this
        # redactor itself produces. A clean stream must still redact correctly.
        r = StreamingRedactor(salt=42, lang="zh")
        out = ""
        for tok in ["用户张伟的", "电话是138", "0013", "8000，", "请处理。"]:
            out += r.feed(tok).downstream_text
        out += r.flush().downstream_text
        assert "13800138000" not in out  # the real input phone was redacted
        original = "用户张伟的电话是13800138000，请处理。"
        assert restore(out, r.aggregate_key(), guard=False) == original

    def test_strict_input_false_stays_silent_on_split_reserved(self):
        # The public opt-out is preserved: strict_input=False disables the scan
        # even for a split reserved value.
        r = StreamingRedactor(salt=42, lang="zh", strict_input=False)
        r.feed("用户张伟的电话是1999912")
        r.feed("3456，请处理。")
        r.flush()  # must not raise
