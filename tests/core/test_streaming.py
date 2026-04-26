"""Tests for streaming restore."""

from argus_redact import redact, redact_pseudonym_llm
from argus_redact.streaming import StreamingRestorer


class TestStreamingRestorer:
    def test_should_restore_at_sentence_boundary(self):
        _, key = redact("电话13812345678", seed=42, mode="fast")
        redacted, _ = redact("电话13812345678", seed=42, mode="fast")

        restorer = StreamingRestorer(key)
        result = restorer.feed(f"结果是{redacted}。下一句")

        assert "13812345678" in result

    def test_should_buffer_incomplete_sentence(self):
        _, key = redact("电话13812345678", seed=42, mode="fast")
        redacted, _ = redact("电话13812345678", seed=42, mode="fast")

        restorer = StreamingRestorer(key)
        result = restorer.feed(f"结果是{redacted}")

        assert result == ""  # no boundary, buffered

    def test_should_flush_remaining(self):
        _, key = redact("电话13812345678", seed=42, mode="fast")
        redacted, _ = redact("电话13812345678", seed=42, mode="fast")

        restorer = StreamingRestorer(key)
        restorer.feed(f"结果是{redacted}")
        result = restorer.flush()

        assert "13812345678" in result

    def test_should_handle_chunk_by_chunk(self):
        _, key = redact("电话13812345678", seed=42, mode="fast")
        redacted, _ = redact("电话13812345678", seed=42, mode="fast")

        restorer = StreamingRestorer(key)
        full_text = f"第一句话{redacted}。第二句话。"

        # Simulate chunked streaming
        output_parts = []
        for i in range(0, len(full_text), 5):
            chunk = full_text[i : i + 5]
            restored = restorer.feed(chunk)
            if restored:
                output_parts.append(restored)
        final = restorer.flush()
        if final:
            output_parts.append(final)

        full_output = "".join(output_parts)
        assert "13812345678" in full_output

    def test_should_handle_empty_key(self):
        restorer = StreamingRestorer({})

        result = restorer.feed("hello world。")

        assert result == "hello world。"

    def test_should_restore_immediately_with_none_strategy(self):
        _, key = redact("电话13812345678", seed=42, mode="fast")
        redacted, _ = redact("电话13812345678", seed=42, mode="fast")

        restorer = StreamingRestorer(key, strategy="none")
        result = restorer.feed(f"结果是{redacted}")

        assert "13812345678" in result  # no buffering, restored immediately

    def test_should_raise_on_unknown_strategy(self):
        import pytest

        with pytest.raises(ValueError, match="Unknown strategy"):
            StreamingRestorer({}, strategy="invalid")


class TestStreamingRestorerRealisticMode:
    """StreamingRestorer must round-trip realistic-mode output (pseudonym-llm profile).

    Realistic fakes have very different shapes than placeholder pseudonyms:
    - zh: 19999... mobile, 999... ID, 滨海市 address, 张三 names
    - en: (555) 555-01XX, 999-XX-XXXX SSN, John Doe, Mockingbird Lane
    - shared: @example.com, 192.0.2.x, 2001:db8::, 00:00:5E:00:53:xx
    Each must restore correctly via the unified key.
    """

    def test_should_restore_zh_realistic_mobile(self):
        text = "请拨打 13912345678 联系王建国。"
        result = redact_pseudonym_llm(text, salt=b"test-salt", lang="zh")

        restorer = StreamingRestorer(result.key)
        restored = restorer.feed(result.downstream_text) + restorer.flush()
        assert restored == text

    def test_should_restore_en_realistic_phone_ssn(self):
        text = "Call (415) 555-1234, SSN 123-45-6789 today."
        result = redact_pseudonym_llm(text, salt=b"test-salt", lang="en")

        restorer = StreamingRestorer(result.key)
        restored = restorer.feed(result.downstream_text) + restorer.flush()
        assert restored == text

    def test_should_restore_email_ip_mac(self):
        text = "Server IP 10.0.0.5 contacts user@company.com via aa:bb:cc:dd:ee:ff."
        result = redact_pseudonym_llm(text, salt=b"test-salt", lang="en")

        restorer = StreamingRestorer(result.key)
        restored = restorer.feed(result.downstream_text) + restorer.flush()
        assert restored == text

    def test_should_restore_display_text_with_markers(self):
        text = "请拨打 13912345678 联系王建国。"
        result = redact_pseudonym_llm(text, salt=b"test-salt", lang="zh")

        # display_text has ⓕ markers — restore() with display_marker= strips them.
        # StreamingRestorer doesn't accept display_marker today; caller can pre-strip
        # or use restore() directly. Verify the contract: passing display_text through
        # the restorer (which does plain restore) leaves markers in place.
        restorer = StreamingRestorer(result.key)
        restored_with_markers = restorer.feed(result.display_text) + restorer.flush()
        # Original key entries don't include the marker, so it stays attached
        assert "ⓕ" in restored_with_markers
        # Stripping markers manually then re-restoring yields original
        from argus_redact.pure.display_marker import strip_display_markers

        clean = strip_display_markers(result.display_text, marker="ⓕ")
        restorer2 = StreamingRestorer(result.key)
        assert restorer2.feed(clean) + restorer2.flush() == text

    def test_should_handle_realistic_value_split_across_chunks(self):
        """Reserved-range fakes can be long (11-digit phone, 18-digit ID).
        If a chunk boundary splits one, sentence buffering must aggregate
        before restore."""
        text = "电话 13912345678 联系。"
        result = redact_pseudonym_llm(text, salt=b"test-salt", lang="zh")

        # Split downstream_text at an arbitrary mid-fake byte
        ds = result.downstream_text
        mid = len(ds) // 2
        chunk1, chunk2 = ds[:mid], ds[mid:]

        restorer = StreamingRestorer(result.key)
        out = restorer.feed(chunk1)  # likely "" (no boundary yet)
        out += restorer.feed(chunk2)
        out += restorer.flush()
        assert out == text
