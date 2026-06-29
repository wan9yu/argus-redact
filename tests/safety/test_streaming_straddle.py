"""Safety: an entity straddling the boundary-less force-flush cut must not leak.

``StreamingRedactor`` buffers input until a sentence boundary, but force-flushes
when the buffer reaches ``DEFAULT_MAX_BUFFER`` (4096) chars without one. If an
entity's head sits just before that cut and its tail arrives in the next chunk,
a naive force-flush emits the head unredacted (neither half matches the full
pattern) — a PII leak. The carry-window fix keeps a trailing window in the
buffer so the entity is wholly present next round and gets redacted.

Detection runs through the real public ``compose.StreamingRedactor`` surface;
each test asserts the raw original PII is ABSENT from the concatenated output.
"""

from __future__ import annotations

from argus_redact.compose import StreamingRedactor
from argus_redact.glue._detect_partial import (
    DEFAULT_MAX_BUFFER,
)
from argus_redact.pure.restore import restore


def _stream(chunks, *, lang="zh", **kw):
    """Feed chunks through a fresh redactor and return concatenated downstream text."""
    r = StreamingRedactor(salt=42, mode="fast", lang=lang, **kw)
    parts = [r.feed(c).downstream_text for c in chunks]
    parts.append(r.flush().downstream_text)
    return "".join(parts), r


def test_phone_straddling_max_buffer_redacts():
    # 4091 boundary-less filler + "电话138" → chunk1 hits exactly 4096 chars with
    # no sentence boundary, forcing a flush. The phone 13800138000 straddles it.
    pad = "啊" * (DEFAULT_MAX_BUFFER - 5)
    out, _ = _stream([pad + "电话138", "00138000，结束。"])
    assert "13800138000" not in out, f"raw phone leaked across the force-flush cut: {out[-40:]!r}"


def test_email_straddling_max_buffer_redacts():
    # English filler keeps the buffer boundary-less; chunk1 hits exactly 4096
    # chars so the force-flush fires with a@bcd.com straddling the cut.
    head = "a@bc"
    pad = "x" * (DEFAULT_MAX_BUFFER - len(head))
    out, _ = _stream([pad + head, "d.com stop."], lang="en")
    assert len(pad + head) == DEFAULT_MAX_BUFFER  # precondition: chunk1 forces a flush
    assert "a@bcd.com" not in out, f"raw email leaked across the force-flush cut: {out[-40:]!r}"


def test_cjk_org_straddling_max_buffer_redacts():
    # A CJK org name straddles the force-flush cut. chunk1 hits exactly 4096
    # chars; the distinctive head of the company name (which sits just before
    # the cut) must not leak unredacted. Today the head fragment emits raw
    # because neither half alone matches the org pattern.
    org = "北京字节跳动科技有限公司"
    prefix = "公司是"
    head, tail = org[:4], org[4:]  # head "北京字节" straddles the cut
    pad = "啊" * (DEFAULT_MAX_BUFFER - len(prefix) - len(head))
    out, _ = _stream([pad + prefix + head, tail + "。结束。"])
    assert len(pad + prefix + head) == DEFAULT_MAX_BUFFER  # precondition: chunk1 forces a flush
    assert head not in out, f"raw org head leaked across the force-flush cut: {out[-40:]!r}"


def test_straddling_entity_round_trips_via_aggregate_key():
    # (a) An entity straddling the carry boundary must still restore cleanly:
    # restore(out, aggregate_key) == the original concatenated input.
    pad = "啊" * (DEFAULT_MAX_BUFFER - 5)
    chunks = [pad + "电话138", "00138000，结束。"]
    out, r = _stream(chunks)
    assert restore(out, r.aggregate_key()) == "".join(chunks)


def test_entity_before_carry_window_emitted_exactly_once():
    # (b) An entity wholly before the len-W cut is emitted once — not duplicated
    # by the carried residual being re-detected next round. Put the phone near
    # the start (well before the carry window) behind a non-boundary comma, then
    # force a flush with a long boundary-less tail.
    phone = "13800138000"
    c1 = "电话" + phone + "，" + "啊" * DEFAULT_MAX_BUFFER
    r = StreamingRedactor(salt=42, mode="fast", lang="zh")
    out = r.feed(c1).downstream_text + r.flush().downstream_text
    assert phone not in out  # redacted, not leaked
    agg = r.aggregate_key()
    fakes = [k for k, v in agg.items() if v == phone and k.startswith("19999")]
    assert fakes, "realistic phone fake should be present"
    assert out.count(fakes[0]) == 1, "the fake must appear exactly once (no double-emit)"


def test_region_evidence_before_cut_not_orphaned():
    # Evidence-gated leak: a bare zh region (西湖区) fires ONLY because a phone is
    # within its proximity window. A sentence boundary lands between the phone and
    # the region, so a naive cut emits the phone in the prefix and carries the bare
    # region — which, re-detected ALONE next round, has lost its corroborating PII
    # and is emitted in plaintext. The snap must carry the candidate together with
    # the evidence that fired it (here: phone BEFORE the region; the region sits in
    # the residual, its evidence in the prefix).
    out, _ = _stream(["我的电话13800138000。西湖区"])
    assert "西湖区" not in out, f"bare region leaked across the evidence cut: {out!r}"
    assert "13800138000" not in out, f"phone leaked: {out!r}"


def test_region_evidence_after_cut_not_orphaned():
    # Same leak, mirror direction: the region is in the prefix and its proximate
    # phone is in the residual. Detecting the prefix alone drops the region below
    # threshold → bare region emitted. The snap must carry the region with the PII.
    out, _ = _stream(["西湖区。我的电话13800138000"])
    assert "西湖区" not in out, f"bare region leaked across the evidence cut: {out!r}"


def test_hobby_cue_across_cut_not_orphaned():
    # The cue-window variant: a hobby (攀岩) fires only because the cue 喜欢 sits in
    # its window. A boundary lands between the cue and the term, so the term is
    # carried bare and re-detected alone (no cue) → leak. A cue is NOT itself a
    # detected entity, so the straddle-snap cannot rescue it — the snap must widen
    # the candidate's danger zone over the cue window and carry both together.
    out, _ = _stream(["我喜欢。攀岩"])
    assert "攀岩" not in out, f"bare hobby leaked across the cue cut: {out!r}"


def test_region_evidence_at_exact_proximity_boundary_not_orphaned():
    # Off-by-one guard: the region fires on a phone at EXACTLY proximity distance 50
    # (the inclusive REGION_PROX_NEAR boundary). The carry margin must exceed 50 by
    # one so the snap's left edge lands strictly inside the phone (not on its end)
    # and the closed-straddle pulls the phone back with the region; at margin 50 the
    # region was orphaned and leaked. phone[0,11] + 50-char filler + region[61,64].
    out, _ = _stream(["13812345678" + "啊" * 50 + "西湖区。"])
    assert "西湖区" not in out, f"region at exact prox distance 50 leaked: {out!r}"
    assert "13812345678" not in out, f"phone leaked: {out!r}"


def test_dense_boundaryless_forceflush_does_not_split_region():
    # Bounded-drain split guard: a dense, boundary-less stream of region+phone
    # repeats hits the max_buffer force-flush. The evidence-widening chains the snap
    # to 0, so the engine must drain — and the drain must be snapped CLOSED-ONLY so
    # it never splits a region straddling the drain point (a split recombines
    # downstream into a verbatim leak). The region must not appear in the output.
    region = "上海浦东新区"
    big = ("我住在" + region + "，电话13800138000，") * 500  # dense, no boundary
    out, _ = _stream([big])
    assert region not in out, "region split/leaked across the bounded drain"


def _pem_key(body_lines: int = 3) -> str:
    """A syntactically valid OPENSSH PEM private key with ``body_lines`` b64 lines."""
    body = "\n".join(
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAA" for _ in range(body_lines)
    )
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"


def test_ssh_private_key_streamed_line_by_line_not_leaked():
    # A multiline PEM private key fed line-by-line: every '\n' is an always-boundary
    # that would commit the BEGIN line + each body line BEFORE the END marker arrives
    # (neither half matches the ssh_private_key pattern alone) → plaintext leak. The
    # opener detector must hold the cut before BEGIN so the whole key is carried and
    # redacted once END is seen (matching batch).
    key = _pem_key(3)
    text = f"my key:\n{key}\ndone."
    chunks = [line + "\n" for line in text.split("\n")]
    out, _ = _stream(chunks, lang="en")
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in out, f"BEGIN line leaked: {out[:80]!r}"
    assert "b3BlbnNzaC1" not in out, f"key body leaked: {out[:120]!r}"


def test_ssh_private_key_larger_than_buffer_not_leaked():
    # A COMPLETE key (END present) whose total length exceeds DEFAULT_MAX_BUFFER but
    # stays within the 10000 body bound (so batch redacts it) must NOT be
    # force-flush-split. The dangerous shape is END with NO trailing boundary after
    # it: the last boundary is the '\n' INSIDE the key, so the snap lands at cut==0
    # and — once END closes the opener — the bounded drain would split the key head
    # unless the ceiling stays raised while ANY BEGIN is present.
    key = _pem_key(90)  # ~5400 chars > DEFAULT_MAX_BUFFER, body < 10000
    assert len(key) > DEFAULT_MAX_BUFFER  # precondition

    # Line-by-line, END the final chunk with NO trailing newline.
    lines = key.split("\n")
    chunks = [(ln + "\n" if i + 1 < len(lines) else ln) for i, ln in enumerate(lines)]
    out, _ = _stream(chunks, lang="en")
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in out, (
        "BEGIN leaked (line-by-line, no trailing boundary)"
    )
    assert "b3BlbnNzaC1" not in out, "body leaked (line-by-line, no trailing boundary)"

    # Single feed of the whole key, then flush — same guarantee.
    out2, _ = _stream([key], lang="en")
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in out2, "BEGIN leaked (single feed)"
    assert "b3BlbnNzaC1" not in out2, "body leaked (single feed)"


def test_ipv4_split_at_internal_dot_after_force_flush_no_leak():
    # An IPv4 (8.8.8.8) straddles the force-flush cut, split at an internal dot.
    # That dot is an ASCII sentence-boundary char, so the OLD _last_boundary_index
    # treated it as a real boundary and emitted the head "8.8" raw — a leak. With
    # the refinement (an ASCII boundary counts only when followed by whitespace),
    # the internal dot does not split the entity.
    pii = "8.8.8.8"
    full = f"server ip {pii} listening"
    p = full.index(pii)
    head = full[: p + 2]  # "...8." — chunk1 ends exactly at MB right after a dot
    pad = "x" * (DEFAULT_MAX_BUFFER - len(head))
    out, _ = _stream([pad + head, full[p + 2 :] + "."], lang="en")
    assert len(pad + head) == DEFAULT_MAX_BUFFER  # precondition: chunk1 forces a flush
    assert pii not in out, f"raw IPv4 leaked across the internal-dot cut: {out[-40:]!r}"


def test_email_split_after_dot_after_force_flush_no_leak():
    # An email a@bcd.com split right after its dot ("a@bcd." | "com"). The dot is
    # an ASCII boundary char appearing inside the entity; the OLD code emitted
    # "a@bcd." raw because it treated the intra-entity dot as a sentence end.
    pii = "a@bcd.com"
    full = f"mail {pii} stop"
    p = full.index(pii)
    head = full[: p + 6]  # "...a@bcd." — chunk1 ends at MB right after the dot
    pad = "x" * (DEFAULT_MAX_BUFFER - len(head))
    out, _ = _stream([pad + head, full[p + 6 :] + "."], lang="en")
    assert len(pad + head) == DEFAULT_MAX_BUFFER  # precondition: chunk1 forces a flush
    assert pii not in out, f"raw email leaked across the internal-dot cut: {out[-40:]!r}"


def test_email_split_at_dot_no_force_flush_no_leak():
    # No force-flush at all — small chunks split exactly at the email's dot.
    # "contact me at a@bcd." | "com please." The trailing dot of chunk1 is at the
    # BUFFER END (no next char yet) → ambiguous, must NOT count as a boundary.
    # The OLD code emitted "...a@bcd." and the tail "com" arrived separately →
    # neither half matched → leak.
    out, _ = _stream(["contact me at a@bcd.", "com please."], lang="en")
    assert "a@bcd.com" not in out, f"raw email leaked across the dot split: {out[-40:]!r}"


def test_dotted_username_email_split_after_dot_no_partial_leak():
    # jane.doe@company.com split after the username dot ("jane." | rest). The dot
    # in the username is intra-entity; "jane." must not be emitted raw as a head.
    out, _ = _stream(["please email jane.", "doe@company.com today."], lang="en")
    assert "jane.doe@company.com" not in out, f"full email leaked: {out[-40:]!r}"
    assert "jane." not in out, f"dotted-username head leaked across the dot: {out[-40:]!r}"


def test_cjk_full_width_boundary_still_splits():
    # CJK full-width 。 always counts as a boundary (it never appears inside an
    # ASCII entity and CJK sentences have no trailing space). A stream split at 。
    # must still flush + redact normally.
    chunks = ["手机13912345678。", "另一个号13987654321。"]
    out, r = _stream(chunks, lang="zh")
    assert "13912345678" not in out
    assert "13987654321" not in out
    assert restore(out, r.aggregate_key()) == "".join(chunks)


def test_normal_sentence_boundary_stream_unchanged():
    # (d) A normal stream that flushes at sentence boundaries (never hits the
    # force-flush) must behave exactly as before: entities redacted, raw absent,
    # round-trips via aggregate_key.
    chunks = [
        "请拨打 13912345678 联系老王。",
        "或拨 13987654321 找老陈。",
        "邮箱 user@company.com 已记录。",
    ]
    out, r = _stream(chunks, lang="zh")
    assert "13912345678" not in out
    assert "13987654321" not in out
    assert "user@company.com" not in out
    assert restore(out, r.aggregate_key()) == "".join(chunks)


def test_open_ended_entity_does_not_grow_buffer_unbounded():
    # REGRESSION (review A2): an open-ended detected span whose span keeps
    # growing as more boundary-less chars arrive used to drive _carry_cut_index
    # to cut<=0 on EVERY feed (the span runs from buffer-start past the target),
    # so the buffer never drained -- it grew monotonically, re-ran _detect on the
    # whole growing buffer each feed (O(n^2)), and feed() eventually raised
    # ValueError from the MAX_INPUT_SIZE guard. The carry must stay bounded.
    #
    # "a@b" opens an email; ".co"*5000 per feed keeps matching as ONE email
    # [0, end] with no sentence boundary, so each feed extends the same span.
    #
    # C1 no-leak strengthening: the email spans the buffer from index 0, so the
    # forced bounded drain must RE-DETECT its emit slice and REDACT the head "a@b"
    # (not drop+leak it raw). Accumulate the output and assert the head is absent.
    r = StreamingRedactor(salt=42, mode="fast", lang="en")
    out = r.feed("a@b").downstream_text
    seg = ".co" * 5000  # 15000 boundary-less chars/feed
    emitted_any = False
    for _ in range(30):
        res = r.feed(seg)  # must NOT raise ValueError (MAX_INPUT_SIZE)
        if res.downstream_text:
            emitted_any = True
        out += res.downstream_text
        # Buffer stays bounded at ~max_buffer + one chunk; never unbounded.
        assert len(r._inc_buffer) < 3 * DEFAULT_MAX_BUFFER, (
            f"buffer grew unbounded: {len(r._inc_buffer)} chars"
        )
    out += r.flush().downstream_text
    # Forward progress: across the run SOME downstream text was emitted (the
    # buffer drained at least once), not always "".
    assert emitted_any, "no downstream text ever emitted -- buffer never drained"
    assert "a@b" not in out, "open-ended email head leaked raw across the forced bounded drain (C1)"


def _mega_github_token(n: int) -> str:
    """A boundary-less github_token (`ghp_` + `n` chars) whose PREFIX still matches.

    No validator, no sentence boundary, length far over DEFAULT_MAX_BUFFER — so the
    force-flush bounded drain MUST split it, and the split head must be re-detected
    and redacted rather than leaked raw.
    """
    return "ghp_" + "A" * n


def test_forceflush_megabuffer_typed_entity_head_not_leaked():
    # C1 (CRITICAL leak regression): a >max_buffer boundary-less github_token fed in
    # small chunks. The buffer hits DEFAULT_MAX_BUFFER with the token spanning
    # [0, len); the bounded drain MUST split it. Before the fix the range-shifted
    # straddler was DROPPED (end > cut) and the ~3840-char head emitted RAW; the fix
    # re-detects the emit slice so the head (still a valid github_token prefix) is
    # redacted. Pin: the distinctive head is ABSENT and restore round-trips.
    token = _mega_github_token(5000)  # 5004 chars > DEFAULT_MAX_BUFFER + carry
    chunks = _chunk(token, 137)  # small chunks, no boundary
    out, r = _stream(chunks, lang="en")
    head = "ghp_" + "A" * 200
    assert head not in out, "github_token head leaked RAW across the forced bounded drain (C1)"
    # Restore round-trips: the redacted head expands back and the documented-edge
    # raw tail is untouched, so the original token is reconstructed exactly.
    assert restore(out, r.aggregate_key()) == token


def test_forceflush_megabuffer_typed_entity_no_leak_en():
    # Fuzz oracle extension: a >max_buffer typed entity (EN — the cross-sentence
    # corpus is zh-only) fed under several chunkings. For EVERY chunking the FULL
    # token original (which batch redacts as one unit) must be ABSENT from the
    # streamed output — before the C1 fix the dropped straddler emitted head+tail raw
    # CONTIGUOUSLY, re-forming the whole token. Restore must round-trip too.
    token = _mega_github_token(6000)  # 6004 chars
    for size in (89, 512, 1777):
        out, r = _stream(_chunk(token, size), lang="en")
        assert token not in out, (
            f"full token re-formed (leaked) in stream output at chunk size {size}"
        )
        assert restore(out, r.aggregate_key()) == token, (
            f"restore round-trip failed at chunk size {size}"
        )


def test_carry_window_range_token_straddle_not_leaked():
    # A ~150-char github_token (length in the 128-256 CARRY_WINDOW range) whose
    # prefix straddles the force-flush chunk boundary. The 'ghp_' prefix (4 chars)
    # sits in the last 256 chars of chunk1 (the carry window); the remaining
    # 'A'*150 arrive in chunk2. CARRY_WINDOW=256 guarantees the prefix is carried
    # so the full 154-char entity is assembled and redacted.
    #
    # Non-vacuity: 'ghp_' alone is not a valid github_token (too short — minimum
    # 36+ alphanumeric chars required after the prefix); 'A'*150 alone is not
    # detected either (no prefix). Without the carry mechanism, neither half would
    # be detected, and the full token would appear reconstructed (consecutively) in
    # the output — so both the `token not in out` assertion AND the aggregate_key
    # check (token IS detected) would fail.
    from argus_redact.glue._detect_partial import _CARRY_WINDOW

    token = "ghp_" + "A" * 150  # 154 chars: 128 < 154 <= 256 = _CARRY_WINDOW
    assert 128 < len(token) <= _CARRY_WINDOW, (
        f"token length {len(token)} must be in (128, _CARRY_WINDOW={_CARRY_WINDOW}]"
    )
    head = token[:4]  # 'ghp_' — not a valid token alone
    tail = token[4:]  # 'A'*150 — no prefix, not detected alone

    # chunk1 is exactly DEFAULT_MAX_BUFFER chars (no sentence boundary), so the
    # force-flush fires. 'ghp_' sits at positions [4092, 4096], entirely within
    # the carry window [DEFAULT_MAX_BUFFER - _CARRY_WINDOW, DEFAULT_MAX_BUFFER].
    pad = "x" * (DEFAULT_MAX_BUFFER - len(head))
    chunk1 = pad + head
    assert len(chunk1) == DEFAULT_MAX_BUFFER  # precondition: triggers force-flush
    chunk2 = tail + " done."

    out, r = _stream([chunk1, chunk2], lang="en")
    assert token not in out, (
        f"raw ~150-char github_token in carry-window range leaked across "
        f"the force-flush boundary: {out[-60:]!r}"
    )
    # Positive guard: the token must have been DETECTED (in aggregate_key), not
    # just absent because it was never assembled. Without carry the token would be
    # absent from aggregate_key AND present (raw) in the output.
    assert token in r.aggregate_key().values(), (
        "token not in aggregate_key — carry failed to assemble the entity"
    )
    assert restore(out, r.aggregate_key()) == chunk1 + chunk2


# ---------------------------------------------------------------------------
# Cross-sentence evidence: detection-context window
# ---------------------------------------------------------------------------

# No-PII, no-gated-term filler (~19 chars/sentence) used to pad a cross-sentence
# cluster past the W=128 hold-back so it COMMITS in a real incremental emit
# (before flush) — not only at end-of-stream. Without enough trailing filler the
# whole text is < W and holds until flush(), which would make these tests inert
# (they'd pass even with the window machinery deleted — they'd just be batch).
_FILLER = "今天天气很好。我们一起去公园散步聊天。"


def _stream_tracked(chunks, *, lang="zh", salt=42, **kw):
    """Stream ``chunks`` and return (full_output, pre_flush_emit_count).

    ``pre_flush_emit_count`` is the number of ``feed()`` calls that returned a
    non-empty ``downstream_text`` — i.e. proof the INCREMENTAL path actually ran
    before ``flush()``. A test that asserts this > 0 fails if the forward
    hold-back / left-context retention is broken in a way that stops incremental
    emission, or if W is set so large nothing ever commits mid-stream.
    """
    r = StreamingRedactor(salt=salt, mode="fast", lang=lang, **kw)
    pre = []
    for c in chunks:
        out = r.feed(c).downstream_text
        if out:
            pre.append(out)
    final = r.flush().downstream_text
    return "".join(pre) + final, len(pre)


def _chunk(text, size):
    chars = list(text)
    return ["".join(chars[i : i + size]) for i in range(0, len(chars), size)]


def test_cross_sentence_committed_incrementally_no_leak():
    """Cross-sentence evidence leaks are closed by the detection-context window —
    PROVEN on inputs longer than W so the gated cluster commits in a real
    incremental emit (before flush), not only at end-of-stream.

    Each case puts the cue and the candidate in DIFFERENT sentences (split by a
    boundary), early in a > W (≈260-char) text padded with neutral filler. The
    window's left-context retention (backward) / forward hold-back (forward) is
    the ONLY reason the candidate is still detected when its sentence commits
    mid-stream; delete it and the candidate emits bare → leak (guarded by the
    W=0 regression in ``test_fuzz_stream_oracle_is_a_real_guard`` below).
    """
    cases = [
        # backward hobby: cue 喜欢 in sentence 1, candidate 攀岩 in sentence 2
        ("我平时很喜欢。攀岩这项户外运动。" + _FILLER * 12, "攀岩"),
        # backward location: cue 住在 in sentence 1, region in sentence 2
        ("我以前就住在那里。上海浦东新区那一带。" + _FILLER * 12, "上海浦东新区"),
        # forward medical: candidate 花生 in sentence 1, cue 过敏 in sentence 2
        ("我之前吃过花生。后来过敏很严重。" + _FILLER * 12, "花生"),
    ]
    for text, term in cases:
        assert len(text) > 128  # precondition: longer than W
        for size in (1, 3, 7):
            out, pre_emits = _stream_tracked(_chunk(text, size))
            assert pre_emits > 0, (
                f"no incremental (pre-flush) emit for {term!r} size={size} — the "
                f"test would be inert (flush-only); window path not exercised"
            )
            assert term not in out, (
                f"cross-sentence leak: {term!r} in streamed output "
                f"(term={term!r}, chunk_size={size})"
            )


def _batch_removed_terms(text: str, *, lang: str = "zh") -> list[str]:
    """Terms that batch ``redact_pseudonym_llm`` makes ABSENT from its output.

    A term is "removed" only if it is absent from the batch downstream text — a
    term that appears multiple times but is detected at only some positions stays
    PRESENT in batch output, so it is (correctly) not in the removed set and
    streaming is allowed to leave its undetected occurrences too. This is the
    apples-to-apples leak-equivalence reference (same detection + same strategy
    as streaming), robust to multi-occurrence filler tokens.
    """
    from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm

    result = redact_pseudonym_llm(text, salt=42, lang=lang, mode="fast")
    return [orig for orig in set(result.key.values()) if orig not in result.downstream_text]


# > W zh texts mixing cross-sentence gated clusters across all four gated types
# (hobby / location / medical / job_title) + closed PII, padded so each cluster
# commits incrementally. These are the fuzz corpus AND the window regression
# fixtures (W=0 below).
_FUZZ_TEXTS = [
    # backward hobby + closed phone
    "我平时很喜欢。攀岩这项户外运动。有事请打电话13800138000。" + _FILLER * 12,
    # backward location + closed phone
    "我以前就住在那里。上海浦东新区那一带。他的手机号13987654321。" + _FILLER * 12,
    # forward medical + job_title cluster + closed phone
    "我之前吃过花生。后来过敏很严重。我同事是一名软件工程师。联系电话13611112222。" + _FILLER * 12,
]


def test_fuzz_stream_leak_equivalence():
    """Fuzz oracle: every term batch removes is absent from the streamed output,
    across random chunk sizes — AND the incremental path actually ran.

    For each > W text and each chunk size, stream it and assert (a) no batch-
    removed term survives in the concatenated downstream (leak-equivalence vs
    batch ``redact_pseudonym_llm``) and (b) at least one ``feed()`` emitted
    before ``flush()`` (the incremental path is exercised, not just flush==batch).
    """
    for text in _FUZZ_TEXTS:
        assert len(text) > 128  # precondition: exercises the incremental path
        removed = _batch_removed_terms(text)
        assert removed  # the corpus must contain removable PII to be meaningful
        for size in (1, 2, 3, 5, 7):
            out, pre_emits = _stream_tracked(_chunk(text, size))
            assert pre_emits > 0, (
                f"no incremental (pre-flush) emit (text len={len(text)}, "
                f"size={size}) — fuzz oracle inert, window path not exercised"
            )
            for term in removed:
                assert term not in out, (
                    f"raw term {term!r} leaked in streamed output "
                    f"(text len={len(text)}, chunk_size={size})"
                )


def test_region_with_long_url_token_sole_evidence_stream_equals_batch():
    # The url_token's ?token= sits >W(128) chars into the URL. With the
    # corroborator allowlist, a url_token no longer corroborates a region in
    # EITHER batch or stream, so the bare region behaves identically in both —
    # no cross-sentence leak. (Region is left as-is because a URL near a
    # district is not evidence the district is a personal address.)
    long_url = "https://corp.example.com/" + ("p" * 160) + "?token=SECRETabc123"
    text = "西湖区。" + long_url + " 后面是一段中文结尾填充内容。"
    out, _ = _stream([text[i : i + 3] for i in range(0, len(text), 3)])
    from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm

    batch = redact_pseudonym_llm(
        text, salt=42, lang="zh", mode="fast", _polluted_input_ok=True
    ).downstream_text
    # The url_token itself is still redacted in both; the region is treated
    # identically in both (no stream-only leak).
    assert ("西湖区" in out) == ("西湖区" in batch), (
        f"stream/batch disagree on region: {out!r} vs {batch!r}"
    )
    assert "SECRETabc123" not in out and "SECRETabc123" not in batch, (
        "url_token must be redacted in both"
    )


def test_fuzz_stream_oracle_is_a_real_guard(monkeypatch):
    """Regression sentinel: the fuzz oracle MUST fail if the detection-context
    window is broken. Break it (W=0 → no left-context retention AND no forward
    hold-back) and assert a cross-sentence gated term now leaks — proving the
    oracle above is not vacuously green.

    The window constant has two read sites: ``_detect_partial._context_cut``
    drives the cut (forward hold-back) and ``streaming.feed`` computes the
    retained left-context (``lo = cut - W``). Both must be zeroed for a full
    break; patching only one leaves the other half of the window intact. This
    pins the window as load-bearing — a future change removing either half flips
    this test (the asserted leak disappears), surfacing the regression.
    """
    import argus_redact.glue._detect_partial as dp
    import argus_redact.streaming as st

    monkeypatch.setattr(dp, "_EVIDENCE_CONTEXT_WINDOW", 0)
    monkeypatch.setattr(st, "_EVIDENCE_CONTEXT_WINDOW", 0)
    leaked_any = False
    for text in _FUZZ_TEXTS:
        removed = _batch_removed_terms(text)
        out, _ = _stream_tracked(_chunk(text, 3))
        if any(term in out for term in removed):
            leaked_any = True
            break
    assert leaked_any, (
        "expected a cross-sentence gated term to leak with the window broken "
        "(W=0); if nothing leaked, the fuzz oracle no longer guards the window"
    )
