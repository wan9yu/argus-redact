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
    _CARRY_WINDOW,
    _bounded_carry,
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
    body = "\n".join("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAA" for _ in range(body_lines))
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
    chunks = [(l + "\n" if i + 1 < len(lines) else l) for i, l in enumerate(lines)]
    out, _ = _stream(chunks, lang="en")
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in out, "BEGIN leaked (line-by-line, no trailing boundary)"
    assert "b3BlbnNzaC1" not in out, "body leaked (line-by-line, no trailing boundary)"

    # Single feed of the whole key, then flush — same guarantee.
    out2, _ = _stream([key], lang="en")
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in out2, "BEGIN leaked (single feed)"
    assert "b3BlbnNzaC1" not in out2, "body leaked (single feed)"


def test_unbounded_token_longer_than_window_is_the_documented_edge():
    # (c) Documented residual edge: a contiguous run LONGER than _CARRY_WINDOW
    # that is not a single detected entity can still split at the force-flush
    # cut. We pin this known limitation so a future change that closes it (or
    # regresses it further) is noticed. The run here straddles the emit cut by
    # more than the window, so the carry cannot keep it whole.
    from argus_redact.glue._detect_partial import _consume_to_boundary

    token = "9" * (2 * _CARRY_WINDOW)  # far longer than the carry window
    total = DEFAULT_MAX_BUFFER + _CARRY_WINDOW + 100
    target = total - _CARRY_WINDOW
    start = target - _CARRY_WINDOW  # run crosses target by a full window on each side
    pad = "x" * (start - len("code"))
    after = "x" * (total - start - len(token))
    combined = pad + "code" + token + after
    emit, residual = _consume_to_boundary("", combined, lang="en", mode="fast")
    # The run is longer than the window AND not a single bounded entity, so the
    # carry-window cannot keep it whole: part stays in emit, part in residual.
    assert token not in emit and token not in residual, (
        "expected the >window run to be split (documented limitation); if this "
        "now holds together, the edge has been closed — update this test"
    )


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
    r = StreamingRedactor(salt=42, mode="fast", lang="en")
    r.feed("a@b")
    seg = ".co" * 5000  # 15000 boundary-less chars/feed
    emitted_any = False
    for _ in range(30):
        res = r.feed(seg)  # must NOT raise ValueError (MAX_INPUT_SIZE)
        if res.downstream_text:
            emitted_any = True
        # Buffer stays bounded at ~max_buffer + one chunk; never unbounded.
        assert len(r._inc_buffer) < 3 * DEFAULT_MAX_BUFFER, (
            f"buffer grew unbounded: {len(r._inc_buffer)} chars"
        )
    # Forward progress: across the run SOME downstream text was emitted (the
    # buffer drained at least once), not always "".
    assert emitted_any, "no downstream text ever emitted -- buffer never drained"


def test_open_ended_entity_at_boundary_path_drains(monkeypatch):
    # MINOR (review A2): the boundary path (boundary >= 0) also had a
    # `if cut <= 0: return "", combined` -- the presence of a real sentence
    # boundary no longer guaranteed a drain once an open-ended span ran from
    # buffer-start past the boundary.
    #
    # Reaching boundary>=0 AND cut<=0 with a REAL detector is not reliably
    # constructible: cut<=0 needs a single DETECTED entity spanning [<=0, >
    # boundary], but a detected span that crosses a real sentence boundary would
    # have to contain a boundary char followed by whitespace (e.g. ". "), which
    # no bounded entity pattern includes -- and the only cut<=0-producing spans
    # are >window unbounded tokens (digit/base64 runs) that contain no such
    # boundary. So we exercise the boundary call site deterministically by
    # forcing _carry_cut_index to return 0 (the cut<=0 snap), and assert
    # _bounded_carry drains once the buffer is at max_buffer. The force-flush
    # path is covered end-to-end by the unbounded-growth test above; this pins
    # the boundary call site uses the same bounded-carry guard, not return "".
    import argus_redact.glue._detect_partial as dp

    monkeypatch.setattr(dp, "_carry_cut_index", lambda *a, **k: 0)
    # A combined string >= max_buffer with a real sentence boundary inside it.
    combined = "x" * (DEFAULT_MAX_BUFFER - 6) + "stop. " + "y" * 100
    assert dp._last_boundary_index(combined) >= 0  # precondition: boundary path
    emit, residual = dp._consume_to_boundary("", combined, lang="en", mode="fast")
    # The buffer must DRAIN (old code returned ("", combined) -> no drain).
    assert residual != combined, "boundary-path cut<=0 still carries everything (no drain)"
    assert emit == combined[: len(combined) - _CARRY_WINDOW]
    assert len(residual) == _CARRY_WINDOW


def test_bounded_carry_small_buffer_carries_all():
    # Below max_buffer: carry everything (safe -- it will grow to max_buffer and
    # drain next round). Returns ("", combined).
    combined = "x" * 100
    emit, residual = _bounded_carry(combined, DEFAULT_MAX_BUFFER)
    assert emit == ""
    assert residual == combined


def test_bounded_carry_at_max_buffer_drains_to_len_minus_window():
    # At/above max_buffer: force-emit the prefix down to the trailing carry
    # window so the buffer is guaranteed to drain (no unbounded growth).
    combined = "x" * DEFAULT_MAX_BUFFER
    emit, residual = _bounded_carry(combined, DEFAULT_MAX_BUFFER)
    target = len(combined) - _CARRY_WINDOW
    assert emit == combined[:target]
    assert residual == combined[target:]
    assert len(residual) == _CARRY_WINDOW
    # Above max_buffer too.
    bigger = "y" * (DEFAULT_MAX_BUFFER + 500)
    emit2, residual2 = _bounded_carry(bigger, DEFAULT_MAX_BUFFER)
    assert emit2 == bigger[: len(bigger) - _CARRY_WINDOW]
    assert len(residual2) == _CARRY_WINDOW
