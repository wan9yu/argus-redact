"""Tests for v0.5.7 ``_detect_partial`` — sentence-bounded incremental detection.

Used by ``_StreamingBuffer`` and ``StreamingRedactor(incremental=True)``.
Private API; tested here directly.
"""

import pytest

from argus_redact.glue._detect_partial import _detect_partial, _last_boundary_index


class TestLastBoundaryIndex:
    def test_no_boundary_returns_minus_one(self):
        assert _last_boundary_index("hello world") == -1

    def test_returns_index_after_boundary(self):
        assert _last_boundary_index("hi.") == 3
        assert _last_boundary_index("hi.\n") == 4
        assert _last_boundary_index("你好。") == 3

    def test_picks_rightmost_boundary(self):
        assert _last_boundary_index("a. b. c") == 5  # after second '.'

    def test_empty_string(self):
        assert _last_boundary_index("") == -1


class TestBufferingBehavior:
    def test_buffers_when_no_boundary(self):
        entities, residual = _detect_partial("hello 1391", lang="en")
        assert entities == []
        assert residual == "hello 1391"

    def test_emits_at_boundary(self):
        # First call buffers
        entities, residual = _detect_partial("电话1391", lang="zh")
        assert entities == []
        # Second call: combined contains boundary at end → emit + detect
        entities, residual = _detect_partial(
            "2345678。", prev_buffer=residual, lang="zh"
        )
        phone_hits = [e for e in entities if e.type == "phone"]
        assert phone_hits, f"phone should be detected after boundary, got {entities}"
        # The emit_text reached the boundary
        assert residual == ""

    def test_residual_carries_partial_to_next_call(self):
        # Three-call sequence — second has boundary, third completes new entity
        ent1, res1 = _detect_partial("电话1391", lang="zh")
        assert ent1 == []
        ent2, res2 = _detect_partial("2345678。然后", prev_buffer=res1, lang="zh")
        assert any(e.type == "phone" for e in ent2)
        # res2 == "然后" (carried since no boundary)
        assert res2 == "然后"

        ent3, res3 = _detect_partial("再加邮箱x@y.com。", prev_buffer=res2, lang="zh")
        assert any(e.type == "email" for e in ent3)


class TestForceFlush:
    def test_force_flush_emits_partial_buffer(self):
        # No boundary, but force_flush=True processes everything
        entities, residual = _detect_partial(
            "电话13912345678", prev_buffer="", lang="zh", force_flush=True
        )
        phone = [e for e in entities if e.type == "phone"]
        assert phone, "force_flush should emit detected entities even without boundary"
        assert residual == ""

    def test_force_flush_with_only_residual(self):
        entities, residual = _detect_partial(
            "", prev_buffer="电话13912345678", lang="zh", force_flush=True
        )
        assert any(e.type == "phone" for e in entities)
        assert residual == ""


class TestMaxBufferOverride:
    def test_max_buffer_force_flushes_no_boundary(self):
        long_text = "x" * 50  # 50 chars, no boundary
        entities, residual = _detect_partial(long_text, lang="zh", max_buffer=20)
        # max_buffer triggered → flushed, residual empty
        assert residual == ""
        # Detection ran (no PII in xxxxx, but no error)
        assert isinstance(entities, list)


class TestEmptyAndEdgeCases:
    def test_empty_text_and_buffer(self):
        entities, residual = _detect_partial("", lang="zh")
        assert entities == []
        assert residual == ""

    def test_lang_passthrough_to_detect(self):
        # Passing lang="en" should detect en-specific patterns (SSN)
        entities, _ = _detect_partial(
            "SSN 123-45-6789.", lang="en"
        )
        assert any(e.type == "ssn" for e in entities)

    def test_offsets_in_emit_text_coordinates(self):
        # Entity offsets should be in (prev_buffer + text)[:boundary] coords.
        ent, res = _detect_partial("电话13912345678。", lang="zh")
        phone = [e for e in ent if e.type == "phone"]
        assert phone, "phone detected"
        e = phone[0]
        emit_text = "电话13912345678。"
        # start/end address into emit_text correctly
        assert emit_text[e.start : e.end] == "13912345678"
