"""Tests for v0.5.7 ``_StreamingBuffer`` — stateful wrapper around
``_detect_partial`` for cross-chunk entity detection.

Private API; tested directly. Public users go through ``StreamingRedactor``.
"""

import pytest

from argus_redact.glue._streaming_buffer import _StreamingBuffer


class TestFeedAndFlush:
    def test_feed_buffers_then_emits_at_boundary(self):
        buf = _StreamingBuffer(lang="zh", mode="fast")
        out1 = buf.feed("电话1391")
        assert out1 == [], f"first chunk has no boundary, got {out1}"
        out2 = buf.feed("2345678。")
        phones = [e for e in out2 if e.type == "phone"]
        assert phones, f"phone should emit at boundary, got {out2}"
        # internal buffer drained
        assert buf._buffer == ""

    def test_flush_emits_remaining_buffer(self):
        buf = _StreamingBuffer(lang="zh", mode="fast")
        buf.feed("电话1391")
        buf.feed("2345678")  # no boundary, still buffered
        flushed = buf.flush()
        assert any(e.type == "phone" for e in flushed)
        assert buf._buffer == ""

    def test_cross_chunk_phone_detection(self):
        buf = _StreamingBuffer(lang="zh", mode="fast")
        out1 = buf.feed("请联系王建国电话1391")  # no boundary
        out2 = buf.feed("2345678。")  # boundary
        all_entities = out1 + out2
        # Phone "13912345678" was split across the two chunks but is detected
        assert any(
            e.type == "phone" and e.text == "13912345678" for e in all_entities
        ), f"cross-chunk phone missing, got {all_entities}"


class TestLangAndMode:
    def test_lang_passes_through(self):
        buf = _StreamingBuffer(lang="en", mode="fast")
        out = buf.feed("My SSN is 123-45-6789.")
        assert any(e.type == "ssn" for e in out), f"en SSN should detect, got {out}"


class TestMaxBuffer:
    def test_max_buffer_forces_flush(self):
        buf = _StreamingBuffer(lang="zh", mode="fast", max_buffer=20)
        # 50 chars, no sentence boundary — exceeds max_buffer
        out = buf.feed("电话13912345678还有信息没有结束没有结束没有结束没有")
        # Triggered max_buffer flush; phone detected
        assert any(e.type == "phone" for e in out)
        assert buf._buffer == ""


class TestFlushIdempotence:
    def test_flush_on_empty_buffer_returns_empty(self):
        buf = _StreamingBuffer(lang="zh", mode="fast")
        assert buf.flush() == []

    def test_flush_after_full_emit_is_noop(self):
        buf = _StreamingBuffer(lang="zh", mode="fast")
        buf.feed("电话13912345678。")  # full emit (boundary at end)
        assert buf.flush() == []
