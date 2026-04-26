"""Tests for streaming restore + streaming redact."""

import pytest

from argus_redact import redact, redact_pseudonym_llm
from argus_redact.glue.redact_pseudonym_llm import PseudonymPollutionError
from argus_redact.pure.restore import restore
from argus_redact.streaming import StreamingRedactor, StreamingRestorer


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


class TestStreamingRedactor:
    """Per-chunk realistic redaction with cross-chunk key continuity.

    Caller MUST feed complete logical units (sentence / paragraph / turn);
    entity boundaries that cross chunk boundaries are not handled in v0.5.2.
    """

    def test_should_redact_single_chunk(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh")
        result = r.feed("请拨打 13912345678 联系王建国。")
        assert "19999" in result.downstream_text
        assert restore(result.downstream_text, result.key) == "请拨打 13912345678 联系王建国。"

    def test_should_keep_same_fake_for_repeated_value_across_chunks(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh")
        # Same phone in two different chunks → same fake in both.
        # Test inputs avoid canonical fake-name table (张三/李四/...) which
        # the pollution scanner would flag as already-redacted output.
        r1 = r.feed("电话 13912345678 是第一段提到的。")
        r2 = r.feed("再次出现 13912345678 在第二段。")

        phone_fakes_1 = [k for k in r1.key if k.startswith("19999")]
        phone_fakes_2 = [k for k in r2.key if k.startswith("19999")]
        assert len(phone_fakes_1) >= 1
        assert len(phone_fakes_2) >= 1
        # Cross-chunk fake for the same original phone must be identical
        assert phone_fakes_1[0] == phone_fakes_2[0]

    def test_should_round_trip_via_aggregate_key(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh")
        chunks = [
            "请拨打 13912345678 联系老王。",
            "或拨 13987654321 找老陈。",
            "身份证 110101199003077651 已核对。",
        ]
        outs = [r.feed(c) for c in chunks]
        joined_in = "".join(chunks)
        joined_out = "".join(o.downstream_text for o in outs)
        assert restore(joined_out, r.aggregate_key()) == joined_in

    def test_should_avoid_collision_across_chunks(self):
        """Two distinct originals must map to distinct fakes in aggregate_key."""
        r = StreamingRedactor(salt=b"test-salt", lang="zh")
        r.feed("电话13912345678。")
        r.feed("电话13987654321。")

        # aggregate_key inverts to {original → fake}; distinct originals must
        # appear under distinct fakes (no two phones share a single fake).
        agg = r.aggregate_key()
        phone_pairs = [(k, v) for k, v in agg.items() if k.startswith("19999")]
        originals = {v for _, v in phone_pairs}
        fakes = {k for k, _ in phone_pairs}
        assert len(originals) == 2
        assert len(fakes) == 2  # one fake per distinct original

    def test_should_reject_polluted_chunk(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh")
        r.feed("正常输入13912345678。")  # produces 19999... in output
        # Feeding text containing a 19999... value should raise (it's a reserved-range fake)
        with pytest.raises(PseudonymPollutionError):
            r.feed("再次出现 19999111222。")

    def test_should_allow_polluted_when_strict_input_false(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh", strict_input=False)
        r.feed("正常输入13912345678。")
        # Should not raise
        r.feed("再次出现 19999111222。")

    def test_should_route_en_chunk_correctly(self):
        r = StreamingRedactor(salt=b"test-salt", lang="en")
        result = r.feed("Call (415) 555-1234, SSN 123-45-6789 today.")
        assert "(555) 555-01" in result.downstream_text
        assert "999-" in result.downstream_text
        assert restore(result.downstream_text, result.key) == "Call (415) 555-1234, SSN 123-45-6789 today."

    def test_should_require_salt(self):
        with pytest.raises(TypeError):
            StreamingRedactor()  # type: ignore[call-arg]
