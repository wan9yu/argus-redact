"""Person-scoring PRECISION / VARIANT / CONSTANTS regression tripwires.

These gates document the zh/en person-scoring CONTRACT *explicitly* and fail
LOUDLY if anyone changes a threshold, weight, base score, proximity bucket, or
the variant-resolution rule. The frozen golden (``test_person_golden_v076.py``)
and the Rust ``#[cfg(test)]`` suites lock the exact bit-identical outputs, but
they encode the constants only implicitly (as opaque expected values across 196
cases). This file names each constant and asserts it by its observable EFFECT,
with a comment stating what breaks if you change it — so a future edit to a
``person_zh.rs`` const trips a test whose NAME tells you which knob moved.

Everything is driven through the shipped path:
``from argus_redact import _core`` →
``_core.detect_person_names_zh`` / ``_core.detect_person_names_en``. PII entities
are built as ``_core.PatternMatch`` (positional ctor). Confidence is compared
with EXACT ``==`` (never ``approx``): the f64 values are load-bearing.

Each gate was tamper-verified: temporarily breaking the guarded const (e.g.
``SCORE_THRESHOLD``, ``W_*``, ``BASE_LEN_*``, ``PROXIMITY_*``) was confirmed to
flip the assertion before the real value was restored. The constructions and
expected values were captured from live ``_core`` (bit-identical to the original
pure-Python reference, proven across T1-T9).
"""

from argus_redact import _core


def _pm(text, type_, start, end, confidence=1.0, layer=1):
    """Build a ``_core.PatternMatch`` for the pii_entities arg (positional ctor)."""
    return _core.PatternMatch(text, type_, start, end, confidence, layer)


def _rows(matches):
    """(text, start, end, confidence) per match, order-preserving. confidence ``==``."""
    return [(m.text, m.start, m.end, m.confidence) for m in matches]


# ── Gate 1: score-precision / threshold boundary ──────────────────────────────
#
# Pins SCORE_THRESHOLD (0.8) as a `>=` comparison AND the non-associative f64
# accumulation (`(base + evidence).min(1.0)` with `evidence` summed in source
# order). The golden locks these values implicitly; here the NAME says it's the
# threshold boundary, so a `>`-vs-`>=` flip or a re-ordered `+=` trips THIS test.


def test_threshold_boundary_at_0_8_passes_just_below_fails():
    # A 2-char base (0.3) reachable ONLY via the proximity bucket:
    #   distance <= 50 (PROXIMITY_NEAR) → +0.5 → 0.3 + 0.5 == 0.8 (== threshold).
    #   distance == 51 → +0.3 (PROXIMITY_MID) → 0.6 < 0.8 → dropped.
    # distance = pii.start - candidate.end; candidate 张三 ends at char 2.
    pad = "，" * 60  # neutral filler — no regex signal fires, proximity only.
    text = "张三" + pad

    # distance 50 → score exactly 0.8 → passes `>= 0.8`. confidence == 0.8 EXACT.
    at = _core.detect_person_names_zh(text, [_pm("13812345678", "phone", 52, 63)])
    assert _rows(at) == [("张三", 0, 2, 0.8)]
    # If SCORE_THRESHOLD becomes `>` (not `>=`) or rises above 0.8, this empties.
    assert at[0].confidence == 0.8

    # distance 51 → score 0.6 → strictly below 0.8 → NOT returned.
    below = _core.detect_person_names_zh(text, [_pm("13812345678", "phone", 53, 64)])
    assert below == []


def test_confidence_is_nonassociative_f64_exact():
    # base 0.3 (2-char) + context-prefix 0.6 → 0.8999999999999999, NOT 0.9.
    # IEEE-754 addition is not associative; this exact tail bit pins the
    # accumulation structure (`base + evidence`, evidence summed in source
    # order). A refactor that reorders the sum or rounds would change this.
    out = _core.detect_person_names_zh("客户张三")
    assert _rows(out) == [("张三", 2, 4, 0.8999999999999999)]
    # Guard against an accidental round-to-0.9 (the "obvious" wrong value).
    assert out[0].confidence != 0.9


# ── Gate 2: variant-resolution ties ───────────────────────────────────────────
#
# Pins the resolution contract from `_resolve_variants`: among passing variants
# at one start, prefer the LONGEST — UNLESS the 3-char "swallowed" a common word
# (3rd char begins a common_words entry), in which case the 2-char wins.


def test_variant_tie_longest_wins_when_no_swallow():
    # 客户何秀珍已登记 → generate_candidates emits 何秀珍 (3) and 何秀 (2) at the
    # same start; context-prefix 客户 pushes both past threshold. No swallow
    # (珍+已 is not a common word) → longest (3-char) wins.
    out = _core.detect_person_names_zh("客户何秀珍已登记")
    # Exact (text, start, end): the 3-char span 2..5, not the 2-char 2..4.
    assert _rows(out) == [("何秀珍", 2, 5, 1.0)]


def test_variant_tie_swallow_drops_to_two_char():
    # 张三预订了机票 → 张三预 (3) swallows "预订" (a common_words entry begins at
    # the 3rd char 预) → resolution drops to the 2-char 张三. A phone PII adjacent
    # (proximity bucket) lifts the 2-char to exactly the 0.8 threshold so it's
    # emitted. If the swallow check were removed, 张三预 (start 0, end 3) would
    # win instead.
    out = _core.detect_person_names_zh("张三预订了机票", [_pm("13800000000", "phone", 0, 0)])
    assert _rows(out) == [("张三", 0, 2, 0.8)]


# ── Gate 3: scoring-constants lock (each by observable effect) ─────────────────


def test_constant_threshold_default_is_0_8():
    # SCORE_THRESHOLD default 0.8 — the OMITTED-threshold call must behave as 0.8.
    # Build a candidate reachable only at <= 0.8 (2-char + proximity-near = 0.8).
    # If the default threshold rose above 0.8, the omitted-arg call would empty.
    text = "张三" + ("，" * 60)
    pii = [_pm("13812345678", "phone", 52, 63)]  # distance 50 → 0.8
    omitted = _core.detect_person_names_zh(text, pii)  # threshold arg omitted
    explicit = _core.detect_person_names_zh(text, pii, None, 0.8)
    assert _rows(omitted) == [("张三", 0, 2, 0.8)]
    assert _rows(omitted) == _rows(explicit)


def test_constant_context_window_observable_behavior():
    # CONTEXT_WINDOW == 20 (chars). NOTE: the 20-vs-21 boundary is NOT directly
    # observable through detect_*, because _CONTEXT_PREFIX is `$`-anchored to the
    # tail of the `before` window — the context word must sit ADJACENT to the
    # name. Any filler between the prefix word and the name breaks the anchor
    # long before the window edge matters (the T1 golden documents the same at
    # window_namestart_19/20/21, all empty). So we pin the GENUINE observable
    # contract: an adjacent context-prefix fires (+0.6), and a single filler char
    # between the prefix and the name removes it entirely.
    adjacent = _core.detect_person_names_zh("客户张明已登记")  # prefix adjacent → fires
    assert _rows(adjacent) == [("张明", 2, 4, 0.8999999999999999)]
    # One filler char ('啊') between 客户 and 张明 → anchor broken → no evidence.
    broken = _core.detect_person_names_zh("客户啊张明已登记")
    assert broken == []


def test_constant_proximity_buckets_50_and_150():
    # PROXIMITY_NEAR == 50 (+W_PROXIMITY_NEAR 0.5) vs PROXIMITY_MID == 150
    # (+W_PROXIMITY_MID 0.3). A bare 2-char name (base 0.3) scored at threshold
    # 0.6 so BOTH buckets emit — and the confidence reveals which bucket fired.
    text = "张三" + ("，" * 200)
    # distance 50 → near bucket → 0.3 + 0.5 == 0.8.
    near = _core.detect_person_names_zh(text, [_pm("1", "phone", 52, 53)], None, 0.6)
    assert _rows(near) == [("张三", 0, 2, 0.8)]
    # distance 51 → mid bucket → 0.3 + 0.3 == 0.6 (NOT 0.8). The score step
    # between distance 50 and 51 pins both the 50-boundary AND the (0.5 vs 0.3)
    # weight gap: near confidence is exactly 0.8, mid is exactly 0.6.
    mid = _core.detect_person_names_zh(text, [_pm("1", "phone", 53, 54)], None, 0.6)
    assert _rows(mid) == [("张三", 0, 2, 0.6)]
    assert near[0].confidence == 0.8 and mid[0].confidence == 0.6


def test_constant_weight_honorific_suffix_0_5():
    # W_HONORIFIC_SUFFIX == 0.5 — honorific-only on a 2-char base: 0.3 + 0.5 = 0.8.
    out = _core.detect_person_names_zh("张三先生你好")
    assert _rows(out) == [("张三", 0, 2, 0.8)]  # base 0.3 + 0.5 → change 0.5 → fails


def test_constant_weight_pii_suffix_0_5():
    # W_PII_SUFFIX == 0.5 — possessive PII keyword after the name: 0.3 + 0.5 = 0.8.
    out = _core.detect_person_names_zh("张三的手机号码")
    assert _rows(out) == [("张三", 0, 2, 0.8)]


def test_constant_weight_paren_phone_0_5():
    # W_PAREN_PHONE == 0.5 — parenthesized mobile after the name: 0.3 + 0.5 = 0.8.
    out = _core.detect_person_names_zh("张三（13812345678）")
    assert _rows(out) == [("张三", 0, 2, 0.8)]


def test_constant_weight_proximity_near_0_5():
    # W_PROXIMITY_NEAR == 0.5 — near-bucket PII only: 0.3 + 0.5 = 0.8.
    text = "张三" + ("，" * 60)
    out = _core.detect_person_names_zh(text, [_pm("13812345678", "phone", 52, 63)])
    assert _rows(out) == [("张三", 0, 2, 0.8)]


def test_constant_weight_context_prefix_0_6():
    # W_CONTEXT_PREFIX == 0.6 — context-prefix only on a 2-char base:
    # 0.3 + 0.6 == 0.8999999999999999 (pins both the 0.6 weight AND the f64 tail).
    out = _core.detect_person_names_zh("客户张三")
    assert _rows(out) == [("张三", 2, 4, 0.8999999999999999)]


def test_constant_base_scores_by_length():
    # BASE_LEN_2 (0.3) / BASE_LEN_3 (0.4) / BASE_LEN_4PLUS (0.5), each isolated
    # by a single mid-bucket proximity signal (+0.3) at threshold 0.6 so the
    # confidence == base + 0.3 reveals the base exactly.
    #   2-char base 0.3 → 0.6 ; 3-char base 0.4 → 0.7 ; 4-char base 0.5 → 0.8.
    pad = "，" * 200

    text2 = "张三" + pad  # 2-char, ends at 2; distance 100 → mid bucket
    out2 = _core.detect_person_names_zh(text2, [_pm("1", "phone", 102, 103)], None, 0.6)
    assert _rows(out2) == [("张三", 0, 2, 0.6)]  # 0.3 + 0.3

    text3 = "何秀珍" + pad  # 3-char, ends at 3; distance 100 → mid bucket
    out3 = _core.detect_person_names_zh(text3, [_pm("1", "phone", 103, 104)], None, 0.6)
    assert _rows(out3) == [("何秀珍", 0, 3, 0.7)]  # 0.4 + 0.3

    text4 = "欧阳娜娜" + pad  # 4-char compound, ends at 4; distance 100 → mid
    out4 = _core.detect_person_names_zh(text4, [_pm("1", "phone", 104, 105)], None, 0.6)
    assert _rows(out4) == [("欧阳娜娜", 0, 4, 0.8)]  # 0.5 + 0.3


def test_constant_zero_evidence_short_circuit_scores_zero():
    # The `if evidence == 0.0: return 0.0` short-circuit — a real surname-led name
    # with NO structural evidence scores exactly 0.0 (declined at L1b at the
    # default 0.8 threshold; left to L2 NER). Two observations pin it:
    #   1. at the default threshold it does NOT surface (0.0 < 0.8).
    assert _core.detect_person_names_zh("张三说了话") == []
    #   2. at threshold 0.0 it surfaces at confidence EXACTLY 0.0 — proving the
    #      short-circuit returned 0.0 (not the 2-char base 0.3 it would carry if
    #      the `evidence == 0.0` guard were removed).
    out = _core.detect_person_names_zh("张三说了话", None, None, 0.0)
    assert _rows(out) == [("张三说", 0, 3, 0.0)]


# ── Gate 4: data-consistency invariant ────────────────────────────────────────
#
# The literal intersection of surnames (single chars) and not_names (2-3 char
# words) IS empty/N/A, as the task notes — so that's not the real invariant. The
# meaningful one is the GENERATOR'S FILTER: not_names is the negative dictionary
# of surname-LED words, so every entry must begin with a single-surname char.
# This documents WHY not_names exists (only surname-led candidates ever need
# negative filtering) and would trip if the pool were rebuilt from a different
# (non-surname-led) word list. Beyond what the data-parity gate's count+sha256
# fingerprint checks (which lock identity, not this structural property).


def test_invariant_every_not_name_starts_with_a_surname_char():
    surnames = set(_core.person_surnames_zh())  # 138 single chars
    not_names = list(_core.person_not_names_zh())
    assert not_names, "not_names pool is empty — fingerprint gate should have caught this"
    offenders = [w for w in not_names if not w or w[0] not in surnames]
    assert offenders == [], f"not_names entries not starting with a surname: {offenders[:10]}"


def test_invariant_no_empty_or_whitespace_pool_entries():
    # An empty/whitespace entry would corrupt the SURNAMES char class or a
    # membership test (e.g. "" in neg would block every candidate). Cheap,
    # high-value structural invariant across the zh pools.
    for name, pool in (
        ("not_names_zh", _core.person_not_names_zh()),
        ("common_words_zh", _core.person_common_words_zh()),
        ("compound_surnames_zh", _core.person_compound_surnames_zh()),
    ):
        bad = [w for w in pool if not w or not w.strip()]
        assert bad == [], f"{name} has empty/whitespace entries"


# ── en gates: contracts not already a NAMED tripwire ──────────────────────────
#
# The en detector has NO scoring — confidence is a fixed 1.0 / 0.9 by rule. Pin
# the two contracts the golden encodes only implicitly: the 1.0-vs-0.9 boundary
# (given-name-led vs surname-only-led) and single-surname-alone → no match.


def test_en_confidence_1_0_vs_0_9_boundary():
    # given-name-led (first token in GIVEN_NAME_SET) → 1.0.
    known = _core.detect_person_names_en("Email John Smith today.")
    assert _rows(known) == [("John Smith", 6, 16, 1.0)]
    # surname-led by a non-given-name capitalized token → 0.9 (NOT 1.0).
    unknown = _core.detect_person_names_en("Quincy Smith arrived.")
    assert _rows(unknown) == [("Quincy Smith", 0, 12, 0.9)]
    assert unknown[0].confidence == 0.9  # flip the 0.9 default → fails


def test_en_single_surname_alone_no_match():
    # A surname with no preceding adjacent capitalized token (i == 0) is
    # intentionally NOT matched — a lone surname is too weak to emit. If the
    # `i == 0: continue` guard were dropped, "Smith" would surface.
    assert _core.detect_person_names_en("Smith arrived.") == []


# ── Gate 5: Python-`re` `\s` parity for U+001C-U+001F (FS/GS/RS/US) ────────────
#
# Python `re`'s `\s` matches the 4 ASCII information-separator control chars
# U+001C-U+001F; fancy_regex's `\s` does NOT. The pre-port Python person scorer
# used `\s` as the optional separator in _CONTEXT_PREFIX (`)[：:\s]?$`) and in the
# gap of _PAREN_PHONE (`^[（(]\s*1...`). A naive `\s` port silently DROPS those 4
# chars, so when one is the SOLE separator the Rust misses the +0.6 / +0.5
# evidence → the candidate scores 0.0 and is dropped → a name the original Python
# DETECTED is now MISSED (silent under-detection — a leak for a redaction lib).
# The fix extends the char classes to `[\s\x1c-\x1f]` (a no-op in Python, where
# `\s` already covers them; restores the 4 chars in fancy_regex). The frozen
# golden has zero control-char bytes, so these cases are the only guard.
#
# Before the fix all of these returned []; after, they detect at the exact
# context-prefix / paren-phone confidence below.


def test_context_prefix_fs_gs_rs_us_separators_match_python_re():
    # _CONTEXT_PREFIX: role word `客户` + a single U+001C-U+001F separator + name.
    # context-prefix fires (+0.6) on a 2-char base (0.3) → 0.8999999999999999
    # (same non-associative f64 tail as the `[：:\s]?` separators above). Each of
    # the 4 information-separator control chars must work identically — Python
    # `re` `\s` matched all 4; fancy_regex `\s` matched NONE before the fix.
    for sep in ("\x1c", "\x1d", "\x1e", "\x1f"):
        out = _core.detect_person_names_zh("客户" + sep + "张三")
        # name at chars 3..5 (客=0, 户=1, sep=2, 张=3, 三=4).
        assert _rows(out) == [("张三", 3, 5, 0.8999999999999999)], f"sep={sep!r}"
        assert out[0].confidence == 0.8999999999999999


def test_paren_phone_control_char_in_gap_matches_python_re():
    # _PAREN_PHONE: name + open paren + a U+001D (GS) control char in the gap +
    # a valid 11-digit mobile. paren-phone fires (+0.5) on a 2-char base (0.3) →
    # 0.8. Before the fix the `\s*` gap rejected the control char → no evidence →
    # dropped. Uses the fullwidth paren `（` the regex accepts.
    out = _core.detect_person_names_zh("张三（\x1d13812345678）")
    assert _rows(out) == [("张三", 0, 2, 0.8)]
    assert out[0].confidence == 0.8
