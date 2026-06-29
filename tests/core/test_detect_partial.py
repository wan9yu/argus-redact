"""Tests for the carry-window boundary helpers in ``_detect_partial``.

Covers ``_last_boundary_index``, the ``streaming_context_cut`` PyO3 binding, and
the ``streaming_emit_possible`` gate that lets ``_context_cut`` skip ``_detect``
on provably-holding feeds.
"""

from unittest.mock import patch

from argus_redact._core_loader import _core
from argus_redact.glue._detect_partial import (
    _EVIDENCE_CONTEXT_WINDOW,
    DEFAULT_MAX_BUFFER,
    _last_boundary_index,
)


class TestLastBoundaryIndex:
    def test_no_boundary_returns_minus_one(self):
        assert _last_boundary_index("hello world") == -1

    def test_returns_index_after_boundary(self):
        # An ASCII boundary counts only when followed by whitespace (a real
        # sentence end). A trailing "." at the buffer end is ambiguous (could be
        # ".com" intra-entity) so it does NOT count until the next char arrives.
        assert _last_boundary_index("hi. ") == 3  # '.' followed by space → real end
        assert _last_boundary_index("hi.\n") == 4  # '\n' always counts
        assert _last_boundary_index("你好。") == 3  # CJK 。 always counts

    def test_ascii_boundary_at_buffer_end_is_ambiguous(self):
        # A trailing ASCII boundary with no following char is ambiguous — wait for
        # the next chunk to disambiguate ". " (sentence end) vs ".com" (entity).
        assert _last_boundary_index("hi.") == -1
        assert _last_boundary_index("a@bcd.") == -1  # intra-entity dot, not a boundary
        assert _last_boundary_index("a@bcd.com listening") == -1  # '.' before 'c'

    def test_cjk_and_newline_always_count(self):
        # CJK full-width punctuation and \n never appear inside ASCII entities and
        # CJK sentences carry no trailing space, so they count even at buffer end.
        assert _last_boundary_index("你好。世界") == 3  # boundary after 。
        assert _last_boundary_index("done\n") == 5
        assert _last_boundary_index("结束！") == 3

    def test_normal_en_sentence_splits_at_dot_space(self):
        # "Hello. World" — the '.' is followed by a space → a real sentence end.
        assert _last_boundary_index("Hello. World") == 6  # after ". "

    def test_picks_rightmost_boundary(self):
        assert _last_boundary_index("a. b. c") == 5  # after second '. '

    def test_empty_string(self):
        assert _last_boundary_index("") == -1


class TestContextCutBinding:
    """PyO3 ``streaming_context_cut`` binding — char-level cut selection.

    The binding returns ``(cut, redetect)``; ``redetect`` is ``True`` only on the
    forced bounded-drain split. All the cases here are boundary / hold / force-flush
    cuts, so each asserts ``redetect`` is ``False``.
    """

    def test_boundary_within_safe_end_returns_cut(self):
        # "abcd。efghij" — 11 chars (a=0..d=3, 。=4, e=5..j=10).
        # W=4: safe_end = 11 - 4 = 7. last boundary ≤ 7 in "abcd。ef" is at index 5
        # (char after 。). snap([], 5) = 5 (no entities to straddle). cut = 5.
        text = "abcd。efghij"
        assert len(text) == 11  # precondition
        assert _core.streaming_context_cut(text, [], 0, 4096, 4, False) == (5, False)

    def test_tail_shorter_than_w_returns_ctx_len(self):
        # "abc" — 3 chars, W=4: safe_end = 3 - 4 < 0 → 0 ≤ ctx_len=0 → hold.
        assert _core.streaming_context_cut("abc", [], 0, 4096, 4, False) == (0, False)

    def test_force_flush_returns_len(self):
        # force_flush=True → emit everything (cut = len regardless of boundaries).
        text = "abc"
        assert _core.streaming_context_cut(text, [], 0, 4096, 4, True) == (3, False)

    def test_evidence_context_window_constant_matches_binding(self):
        # _EVIDENCE_CONTEXT_WINDOW is the W used by StreamingRedactor.
        assert _EVIDENCE_CONTEXT_WINDOW == 128

    def test_ctx_len_respected(self):
        # ctx_len=3 means the first 3 chars are already-emitted left-context.
        # W=4, "abcd。efghij" (11 chars): safe_end=7, boundary=5 > ctx_len=3 → cut=5.
        assert _core.streaming_context_cut("abcd。efghij", [], 3, 4096, 4, False) == (5, False)

    def test_entity_straddle_snaps_cut_back(self):
        # W=4, text has boundary at 5 but an entity spans [3, 8).
        # snap(target=5) → 3 (entity start); cut = max(3, ctx_len=0) = 3.
        text = "abcd。efghij"
        spans = [(3, 8, "phone")]
        result = _core.streaming_context_cut(text, spans, 0, 4096, 4, False)
        assert result == (3, False)

    def test_forced_bounded_drain_split_sets_redetect(self):
        # A boundary-less buffer AT max_buffer whose sole entity spans [0, len) past
        # the drain point: snap chains to 0 ≤ ctx_len, so the cut is FORCED to the
        # raw len - CARRY_WINDOW and ``redetect`` is True (the emit slice must be
        # re-detected). max_buffer=20, W=4, CARRY_WINDOW=256 is too big here, so use
        # a buffer ≥ DEFAULT_MAX_BUFFER (4096) and CARRY_WINDOW (256).
        text = "x" * DEFAULT_MAX_BUFFER
        spans = [(0, DEFAULT_MAX_BUFFER, "jwt")]  # one entity spanning the whole buffer
        cut, redetect = _core.streaming_context_cut(
            text, spans, 0, DEFAULT_MAX_BUFFER, _EVIDENCE_CONTEXT_WINDOW, False
        )
        assert cut == DEFAULT_MAX_BUFFER - 256  # raw len - CARRY_WINDOW (forced split)
        assert redetect is True


class TestEmitPossibleBinding:
    """PyO3 ``streaming_emit_possible`` binding."""

    def test_short_buffer_no_boundary_returns_false(self):
        # Buffer shorter than W with no boundary → emit_possible is False.
        assert (
            _core.streaming_emit_possible("hello world", 0, DEFAULT_MAX_BUFFER, 128, False) is False
        )

    def test_force_flush_returns_true(self):
        assert _core.streaming_emit_possible("x", 0, DEFAULT_MAX_BUFFER, 128, True) is True

    def test_buffer_at_max_returns_true(self):
        text = "x" * DEFAULT_MAX_BUFFER
        assert _core.streaming_emit_possible(text, 0, DEFAULT_MAX_BUFFER, 128, False) is True

    def test_boundary_in_safe_window_returns_true(self):
        # 256 chars of filler + 。 + 128 more chars → safe_end = 385 - 128 = 257;
        # boundary at 257 > ctx_len=0 → emit_possible True.
        text = "啊" * 256 + "。" + "啊" * 128
        assert _core.streaming_emit_possible(text, 0, DEFAULT_MAX_BUFFER, 128, False) is True


class TestDetectSkipGate:
    """Non-vacuous proof that ``_detect`` is NOT called on a provably-holding feed.

    The gate in ``_context_cut`` must skip ``_detect`` when ``streaming_emit_possible``
    returns False, and must still call ``_detect`` when an emit IS possible.
    """

    def test_detect_not_called_on_hold_feed(self):
        # A short boundary-less buffer (< W chars, no sentence boundary) provably
        # holds → emit_possible=False → _detect must NOT be called.
        import argus_redact.glue._detect_partial as _dp
        from argus_redact.glue._detect_partial import _context_cut

        short = "hello world"  # 11 chars, no boundary, W=128 → provably holds
        with patch.object(_dp, "_detect") as mock_detect:
            cut, redetect, entities = _context_cut(
                short, 0, lang="en", mode="fast", names=None, types=None, types_exclude=None
            )
        mock_detect.assert_not_called()
        assert cut == 0
        assert redetect is False
        assert entities == []

    def test_detect_called_when_emit_possible(self):
        # A buffer with a sentence boundary in the safe window → emit_possible=True
        # → _detect MUST be called (the gate must not over-skip).
        import argus_redact.glue._detect_partial as _dp
        from argus_redact.glue._detect_partial import _context_cut

        # 256 chars filler + 。 + 128 chars → safe_end = 385 - 128 = 257; boundary at
        # 257 > ctx_len=0 → emit_possible True → _detect runs.
        text = "啊" * 256 + "。" + "啊" * 128
        sentinel = ([], [], {}, {})  # (_detect returns (entities, langs, timing, stats))
        with patch.object(_dp, "_detect", return_value=sentinel) as mock_detect:
            _context_cut(
                text, 0, lang="zh", mode="fast", names=None, types=None, types_exclude=None
            )
        mock_detect.assert_called_once()
