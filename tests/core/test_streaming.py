"""Tests for streaming restore + streaming redact."""

import os
import re
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from argus_redact import PseudonymPollutionError, redact, redact_pseudonym_llm
from argus_redact.exceptions import SecurityWarning
from argus_redact.pure.restore import restore
from argus_redact.streaming import StreamingRedactor, StreamingRestorer

# Matches the reserved-range audit-space placeholder shape emitted by the
# "remove" strategy (e.g. "P-21929" for person, "PHON-76495" for phone,
# "[TYPE-NNNNN]" style prefixes) — never a shape a realistic-strategy faker
# would legitimately produce.
_AUDIT_PLACEHOLDER_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Z][A-Z_]*-\d{4,6}(?![0-9])")

_SRC_DIR = Path(__file__).resolve().parents[2] / "src"


class TestStreamingRestorer:
    def test_should_restore_at_sentence_boundary(self):
        _, key = redact("电话13812345678", salt=42, mode="fast")
        redacted, _ = redact("电话13812345678", salt=42, mode="fast")

        restorer = StreamingRestorer(key)
        result = restorer.feed(f"结果是{redacted}。下一句")

        assert "13812345678" in result

    def test_should_buffer_incomplete_sentence(self):
        _, key = redact("电话13812345678", salt=42, mode="fast")
        redacted, _ = redact("电话13812345678", salt=42, mode="fast")

        restorer = StreamingRestorer(key)
        result = restorer.feed(f"结果是{redacted}")

        assert result == ""  # no boundary, buffered

    def test_should_flush_remaining(self):
        _, key = redact("电话13812345678", salt=42, mode="fast")
        redacted, _ = redact("电话13812345678", salt=42, mode="fast")

        restorer = StreamingRestorer(key)
        restorer.feed(f"结果是{redacted}")
        result = restorer.flush()

        assert "13812345678" in result

    def test_should_handle_chunk_by_chunk(self):
        _, key = redact("电话13812345678", salt=42, mode="fast")
        redacted, _ = redact("电话13812345678", salt=42, mode="fast")

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
        _, key = redact("电话13812345678", salt=42, mode="fast")
        redacted, _ = redact("电话13812345678", salt=42, mode="fast")

        restorer = StreamingRestorer(key, strategy="none")
        result = restorer.feed(f"结果是{redacted}")

        assert "13812345678" in result  # no buffering, restored immediately

    def test_should_raise_on_unknown_strategy(self):
        import pytest

        with pytest.raises(ValueError, match="Unknown strategy"):
            StreamingRestorer({}, strategy="invalid")


class TestStreamingRestorerSecurityWarning:
    """H6: streaming restore runs unguarded (guard=False, no per-call anchor is
    possible mid-stream) — it must emit a one-time SecurityWarning the first
    time it actually reinserts a pseudonym, not stay silent forever."""

    def test_should_warn_once_on_first_substitution_then_stay_quiet(self):
        _, key1 = redact("电话13812345678", salt=b"test-salt-a", mode="fast")
        redacted1, _ = redact("电话13812345678", salt=b"test-salt-a", mode="fast")
        _, key2 = redact("电话13912345678", salt=b"test-salt-b", mode="fast")
        redacted2, _ = redact("电话13912345678", salt=b"test-salt-b", mode="fast")
        merged_key = {**key1, **key2}

        restorer = StreamingRestorer(merged_key)

        with pytest.warns(SecurityWarning, match="streaming restore is unguarded"):
            first = restorer.feed(f"结果是{redacted1}。")
        assert "13812345678" in first

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            second = restorer.feed(f"另一个{redacted2}。")
        assert "13912345678" in second
        assert not any(issubclass(w.category, SecurityWarning) for w in caught)

    def test_should_not_warn_when_nothing_is_substituted(self):
        restorer = StreamingRestorer({})

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = restorer.feed("hello world。")
        assert result == "hello world。"
        assert not any(issubclass(w.category, SecurityWarning) for w in caught)

    def test_should_warn_once_across_flush(self):
        _, key = redact("电话13812345678", salt=b"test-salt-c", mode="fast")
        redacted, _ = redact("电话13812345678", salt=b"test-salt-c", mode="fast")

        restorer = StreamingRestorer(key)
        with pytest.warns(SecurityWarning, match="streaming restore is unguarded"):
            result = restorer.feed(f"结果是{redacted}") + restorer.flush()
        assert "13812345678" in result


class TestStreamingRestorerMaxBuffer:
    """H7: an LLM reply that never emits a sentence terminator must not buffer
    the whole stream unboundedly — the internal buffer is force-flushed once
    it grows past ``max_buffer``."""

    def test_should_bound_buffer_when_no_boundary_ever_appears(self):
        restorer = StreamingRestorer({}, max_buffer=64)

        for _ in range(50):
            restorer.feed("x" * 10)  # no boundary chars at all
            assert len(restorer._buffer) <= restorer._max_buffer

    def test_default_max_buffer_mirrors_streaming_redactor(self):
        from argus_redact.glue._detect_partial import DEFAULT_MAX_BUFFER

        restorer = StreamingRestorer({})
        assert restorer._max_buffer == DEFAULT_MAX_BUFFER == 4096

    def test_force_flush_does_not_split_a_pseudonym_token(self):
        """Force-flushing past the cap must not corrupt the eventual restore —
        no fake token may be split across the force-flush boundary."""
        text = "填充" * 300 + "电话13912345678。"
        result = redact_pseudonym_llm(text, salt=b"test-salt", lang="zh")
        ds = result.downstream_text
        # Precondition: no sentence boundary until the trailing "。" — this
        # actually exercises force-flush (not the normal boundary path).
        assert not any(b in ds[:-1] for b in StreamingRestorer.BOUNDARIES)

        restorer = StreamingRestorer(result.key, max_buffer=64)
        out = ""
        for i in range(0, len(ds), 7):
            out += restorer.feed(ds[i : i + 7])
            assert len(restorer._buffer) <= restorer._max_buffer + 32
        out += restorer.flush()
        assert out == text


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
        ds = result.downstream_text

        # Find the realistic phone fake and split deliberately mid-fake.
        fake = next(k for k in result.key if k.startswith("19999"))
        fake_start = ds.index(fake)
        split = fake_start + len(fake) // 2
        chunk1, chunk2 = ds[:split], ds[split:]

        # Pin the precondition: chunk1 must NOT contain a sentence boundary
        # (otherwise the test wouldn't actually exercise mid-fake buffering).
        assert not any(b in chunk1 for b in StreamingRestorer.BOUNDARIES)

        restorer = StreamingRestorer(result.key)
        out = restorer.feed(chunk1)
        assert out == "", "chunk1 alone should buffer (no sentence boundary)"
        out += restorer.feed(chunk2)
        out += restorer.flush()
        assert out == text


class TestStreamingRedactor:
    """Per-chunk realistic redaction with cross-chunk key continuity.

    The detection-context window (W = 128 chars) keeps ±W of context around
    every emit, so streaming evidence-gated detection equals batch. The
    hold-back means short texts (< W chars) are held until ``flush()`` or
    until enough following context arrives — tests use ``feed() + flush()``
    to collect the full output.
    """

    def test_should_redact_single_chunk(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh")
        # Short text (< 128 chars) is held for context; flush() drains it.
        r.feed("请拨打 13912345678 联系王建国。")
        result = r.flush()
        assert "19999" in result.downstream_text
        assert (
            restore(result.downstream_text, r.aggregate_key(), guard=False)
            == "请拨打 13912345678 联系王建国。"
        )

    def test_should_keep_same_fake_for_repeated_value_across_chunks(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh")
        # Both short chunks are held; flush() processes them together.
        r.feed("电话 13912345678 是第一段提到的。")
        r.feed("再次出现 13912345678 在第二段。")
        r.flush()

        # aggregate_key must contain exactly ONE fake for 13912345678
        agg = r.aggregate_key()
        phone_fakes = [k for k, v in agg.items() if v == "13912345678" and k.startswith("19999")]
        assert len(phone_fakes) == 1, (
            f"same original must map to exactly one fake; got {phone_fakes}"
        )

    def test_should_round_trip_via_aggregate_key(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh")
        chunks = [
            "请拨打 13912345678 联系老王。",
            "或拨 13987654321 找老陈。",
            "身份证 110101199003077651 已核对。",
        ]
        outs = [r.feed(c) for c in chunks]
        final = r.flush()
        joined_in = "".join(chunks)
        joined_out = "".join(o.downstream_text for o in outs) + final.downstream_text
        assert restore(joined_out, r.aggregate_key(), guard=False) == joined_in

    def test_should_avoid_collision_across_chunks(self):
        """Two distinct originals must map to distinct fakes in aggregate_key."""
        r = StreamingRedactor(salt=b"test-salt", lang="zh")
        r.feed("电话13912345678。")
        r.feed("电话13987654321。")
        r.flush()  # emit to populate aggregate_key

        agg = r.aggregate_key()
        phone_pairs = [(k, v) for k, v in agg.items() if k.startswith("19999")]
        originals = {v for _, v in phone_pairs}
        fakes = {k for k, _ in phone_pairs}
        assert len(originals) == 2
        assert len(fakes) == 2  # one fake per distinct original

    def test_should_reject_polluted_chunk(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh")
        r.feed("正常输入13912345678。")  # holds; no 19999... yet in input
        # Feeding text containing a 19999... value raises via the eager check.
        with pytest.raises(PseudonymPollutionError):
            r.feed("再次出现 19999111222。")

    def test_should_allow_polluted_when_strict_input_false(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh", strict_input=False)
        r.feed("正常输入13912345678。")
        # Should not raise with strict_input=False
        r.feed("再次出现 19999111222。")

    def test_should_route_en_chunk_correctly(self):
        # The sentence ends with "today." — a bare trailing '.' at the buffer end
        # is ambiguous (could be ".com"), so feed() defers it; flush() drains the
        # tail at end-of-stream (the documented usage). Concatenate both emits.
        r = StreamingRedactor(salt=b"test-salt", lang="en")
        out = r.feed("Call (415) 555-1234, SSN 123-45-6789 today.").downstream_text
        out += r.flush().downstream_text
        assert "(555) 555-01" in out
        assert "999-" in out
        assert (
            restore(out, r.aggregate_key(), guard=False)
            == "Call (415) 555-1234, SSN 123-45-6789 today."
        )

    def test_should_require_salt(self):
        with pytest.raises(TypeError):
            StreamingRedactor()  # type: ignore[call-arg]

    def test_should_accept_reserved_names_override(self):
        """Caller can disable canonical fake-name detection across all chunks."""
        r = StreamingRedactor(
            salt=b"test",
            lang="zh",
            mode="fast",
            names=["张三"],
            reserved_names={"person_zh": ()},  # disable zh canonical names
        )
        # 张三 is in canonical list — without override, the chunk would be
        # flagged as polluted. With override it passes through. flush() emits.
        r.feed("客户张三电话13912345678。")
        result = r.flush()
        assert "13912345678" not in result.downstream_text


class TestIncrementalKwargRemoved:
    """v0.6.0: incremental=False is removed; passing it must raise TypeError."""

    def test_incremental_kwarg_no_longer_accepted(self):
        import pytest

        from argus_redact.streaming import StreamingRedactor

        with pytest.raises(TypeError, match="incremental"):
            StreamingRedactor(salt=b"x", incremental=False)


class TestStreamingRedactorIncremental:
    """v0.5.7: opt-in incremental mode handles entities split across chunks.
    v0.5.8: incremental is now the default.
    v0.6.0: incremental is the only mode; opt-out kwarg removed.
    v0.7.x: detection-context window (W=128) added — texts shorter than W are
    held until flush() or until ≥ W chars of forward context arrive.
    """

    def test_default_mode_is_incremental_in_v058(self):
        """With the detection-context window, feed()+flush() together redact."""
        r = StreamingRedactor(salt=b"x", lang="zh", mode="fast")
        # Short text (< W=128) is held for context; combine feed+flush output.
        feed_out = r.feed("电话13912345678。")
        flush_out = r.flush()
        combined = feed_out.downstream_text + flush_out.downstream_text
        assert "13912345678" not in combined
        assert combined != ""

    def test_cross_chunk_phone_zh(self):
        r = StreamingRedactor(salt=b"x", lang="zh", mode="fast")
        out1 = r.feed("电话1391")  # no boundary → buffered
        assert out1.downstream_text == ""
        out2 = r.feed("2345678。")  # boundary present but buffer < W → still held
        # Phone must not appear in any emitted text; flush() drains it
        final = r.flush()
        combined = out2.downstream_text + final.downstream_text
        assert "13912345678" not in combined, (
            f"phone should be redacted across chunks, got {combined!r}"
        )

    def test_cross_chunk_id_zh(self):
        r = StreamingRedactor(salt=b"x", lang="zh", mode="fast")
        # A valid Chinese id (110101199003074610 — correct checksum) split mid-value
        # across two chunks. The id must be redacted, never emitted raw across the cut.
        out = r.feed("身份证号码11010").downstream_text
        out += r.feed("1199003074610。").downstream_text
        out += r.flush().downstream_text
        assert "110101199003074610" not in out, f"id should be redacted across chunks, got {out!r}"

    def test_cross_chunk_email(self):
        r = StreamingRedactor(salt=b"x", lang="en", mode="fast")
        r.feed("Email me at user@")
        out = r.feed("company.com.")
        final = r.flush()
        combined = out.downstream_text + final.downstream_text
        assert "user@company.com" not in combined, (
            f"email should be redacted across chunks, got {combined!r}"
        )

    def test_flush_drains_remaining_buffer(self):
        r = StreamingRedactor(salt=b"x", lang="zh", mode="fast")
        r.feed("最后一句没有标点，电话1391")
        flushed = r.feed("2345678")  # still no boundary, and buffer < W → held
        assert flushed.downstream_text == ""
        final = r.flush()
        assert "13912345678" not in final.downstream_text, (
            f"flush should emit pending entity, got {final.downstream_text!r}"
        )

    def test_shift_entities_clamps_left_straddler_to_in_range_tail(self):
        # Clamp restore-safety (C1 face 3), mirroring the core ``shift_spans`` unit
        # test: an entity whose head reaches back into the already-emitted
        # left-context (start < lo) is clamped to start=0 AND its text TRUNCATED to
        # the in-range tail, so the minted fake maps to exactly the emitted chars.
        # Without truncation key[fake] = the FULL original while only the tail is
        # spliced → restore expands the fake over the already-emitted head (a
        # round-trip corruption).
        from argus_redact._types import PatternMatch

        e = PatternMatch(text="abcdefgh", type="phone", start=2, end=10)  # buffer [2,10)
        out = StreamingRedactor._shift_entities([e], 5, 12)  # lo=5: head "abc" is left-context
        assert len(out) == 1
        assert out[0].start == 0
        assert out[0].end == 5
        assert out[0].text == "defgh"  # dropped lo-start=3 head chars

    def test_flush_idempotent_on_empty(self):
        r = StreamingRedactor(salt=b"x", lang="zh", mode="fast")
        # Short sentence (< W) is held; first flush() drains it.
        r.feed("电话13912345678。")
        r.flush()  # drain the held buffer
        # Second flush on now-empty buffer is the no-op.
        result = r.flush()
        assert result.downstream_text == ""
        assert result.key == {}

    def test_aggregate_key_preserved_across_incremental_chunks(self):
        """Same original across chunks must reuse the same fake (not minted twice)."""
        r = StreamingRedactor(salt=b"x", lang="zh", mode="fast")
        r.feed("第一次提到13912345678。")
        r.feed("第二次还是13912345678。")
        r.flush()  # emit to populate aggregate_key

        agg = r.aggregate_key()
        # The realistic fake (199-xx reserved-range) must exist and be unique.
        downstream_fakes = [k for k, v in agg.items() if v == "13912345678" and k.startswith("199")]
        assert downstream_fakes, "realistic phone fake present in aggregate key"
        assert len(downstream_fakes) == 1, (
            f"same original must mint exactly one fake; got {downstream_fakes}"
        )


class TestStreamingRedactorRealisticKeyIsolation:
    """C9 (v0.8.2): the realistic pass must never resolve a recurring name to
    an audit-space placeholder in downstream_text.

    ``_accumulated_key`` (the UNIFIED key) holds BOTH the realistic fake and
    the audit placeholder for the same original. Its reverse index (Rust
    HashMap, built by inverting the whole dict — see ``ReplaceSession::new``
    in ``crates/argus-redact-core/src/replace.rs``) can resolve a recurring
    original to EITHER fake, non-deterministically. The fix threads the
    exact realistic-only ``result.downstream_key`` (populated by
    ``redact_pseudonym_llm`` from the realistic pass's own ``key``, before it
    is unioned with the audit pass's key) into a separate
    ``_accumulated_realistic_key``, so the realistic pass's ``existing_key``
    never contains an audit placeholder at all — no reverse-index ambiguity
    is structurally possible, regardless of hash seed.
    """

    def test_should_not_leak_audit_placeholder_when_name_recurs_across_flushes(self):
        r = StreamingRedactor(salt=b"test-salt", lang="zh", mode="fast")
        r.feed("请拨打 13912345678 联系王建国。")
        out1 = r.flush()
        r.feed("王建国的电话是13911112222,请再次确认。")
        out2 = r.flush()
        combined = out1.downstream_text + out2.downstream_text
        assert not _AUDIT_PLACEHOLDER_RE.search(combined), (
            f"audit placeholder leaked into downstream_text: {combined!r}"
        )

    def test_aggregate_key_still_has_both_realistic_and_audit_spaces(self):
        """The fix must not strip audit space from the returned unified key —
        restore() needs both the realistic fake AND the audit placeholder
        mapped back to the same original."""
        r = StreamingRedactor(salt=b"test-salt", lang="zh", mode="fast")
        r.feed("请拨打 13912345678 联系王建国。")
        r.flush()
        agg = r.aggregate_key()
        fakes_for_name = [k for k, v in agg.items() if v == "王建国"]
        assert len(fakes_for_name) == 2, (
            f"expected exactly one realistic fake and one audit placeholder "
            f"for 王建国, got {fakes_for_name}"
        )
        audit_fakes = [k for k in fakes_for_name if _AUDIT_PLACEHOLDER_RE.fullmatch(k)]
        realistic_fakes = [k for k in fakes_for_name if not _AUDIT_PLACEHOLDER_RE.fullmatch(k)]
        assert len(audit_fakes) == 1, fakes_for_name
        assert len(realistic_fakes) == 1, fakes_for_name

    def test_seed_sweep_never_leaks_audit_placeholder_into_downstream(self):
        """Determinism: the original bug's leak was hash-seed dependent
        (measured ~60% leak rate pre-fix over 41 seeds via a scratch harness
        feeding the unified key as existing_key=). Sweep PYTHONHASHSEED over a
        fresh subprocess per value; the fix must be leak-free for every seed
        because the audit-space placeholder is structurally never fed into
        the realistic pass's existing_key at all (not merely less likely to
        be picked by a random HashMap iteration order).
        """
        script = (
            f"import sys; sys.path.insert(0, {str(_SRC_DIR)!r})\n"
            "from argus_redact.streaming import StreamingRedactor\n"
            'r = StreamingRedactor(salt=b"test-salt", lang="zh", mode="fast")\n'
            'r.feed("请拨打 13912345678 联系王建国。")\n'
            "out1 = r.flush()\n"
            'r.feed("王建国的电话是13911112222,请再次确认。")\n'
            "out2 = r.flush()\n"
            'print(out1.downstream_text + "|" + out2.downstream_text, end="")\n'
        )
        leaking_seeds = []
        for seed in range(26):
            proc = subprocess.run(
                [sys.executable, "-c", script],
                env={**os.environ, "PYTHONHASHSEED": str(seed)},
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert proc.returncode == 0, (
                f"subprocess failed for seed={seed}: {proc.stderr}"
            )
            if _AUDIT_PLACEHOLDER_RE.search(proc.stdout):
                leaking_seeds.append((seed, proc.stdout))
        assert leaking_seeds == [], f"audit placeholder leaked at seeds: {leaking_seeds}"
