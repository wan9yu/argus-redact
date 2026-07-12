"""A near_miss whose span is already claimed by an accepted entity of another type is noise.

This is the general rule that replaces `neutral_except` — a hand-maintained per-pattern
denylist naming other languages, which had to be updated whenever a new pack shipped a
pattern for the same value, and which only worked for zh-alone (not ["zh","en"], not auto).
"""

from argus_redact._core_loader import _core
from argus_redact._types import PatternMatch
from argus_redact.pure.hints import produce_hints


def _pm(text, type_, start, conf=0.9, layer=1):
    return PatternMatch(
        text=text, type=type_, start=start, end=start + len(text), confidence=conf, layer=layer
    )


def _kinds(hints):
    return [h["type"] if isinstance(h, dict) else h.type for h in hints]


def _to_core(matches):
    """Mirror Python PatternMatch into _core.PatternMatch (same fields)."""
    return [
        _core.PatternMatch(m.text, m.type, m.start, m.end, m.confidence, m.layer) for m in matches
    ]


def test_near_miss_suppressed_when_span_claimed_by_another_type():
    text = "卡号 6217000000000001"
    pan = "6217000000000001"
    accepted = [_pm(pan, "bank_card", 3)]
    near_misses = [_pm(pan, "credit_card", 3, conf=0.3)]  # en validator rejects, zh accepts
    hints = produce_hints(accepted, text, near_misses=near_misses)
    assert not any("near_miss" in str(k) for k in _kinds(hints))


def test_near_miss_kept_when_nothing_claims_the_span():
    text = "id 110101199003078888"
    near_misses = [_pm("110101199003078888", "id_number", 3, conf=0.3)]
    hints = produce_hints([], text, near_misses=near_misses)
    assert any("near_miss" in str(k) for k in _kinds(hints))


def test_near_miss_kept_when_the_claimer_is_the_SAME_type():
    """Same type = the same detector disagreeing with itself; not the case we suppress."""
    text = "id 110101199003078888"
    span = "110101199003078888"
    hints = produce_hints(
        [_pm(span, "id_number", 3)], text, near_misses=[_pm(span, "id_number", 3, conf=0.3)]
    )
    assert any("near_miss" in str(k) for k in _kinds(hints))


def test_near_miss_kept_when_another_type_merely_TOUCHES_the_span():
    """Touching is not overlapping: `entity.end == near_miss.start` must KEEP the hint.

    The boundary the suppression rule must not cross. An off-by-one (`<` → `<=`) in the
    overlap test passes every other case here while silently swallowing a hint that sits
    flush against an unrelated entity.
    """
    text = "13800138000110101199003078888"
    phone, idn = "13800138000", "110101199003078888"

    # entity ends exactly where the near-miss starts
    hints = produce_hints([_pm(phone, "phone", 0)], text, near_misses=[_pm(idn, "id_number", 11)])
    assert any("near_miss" in str(k) for k in _kinds(hints))

    # near-miss ends exactly where the entity starts
    hints = produce_hints([_pm(idn, "phone", 11)], text, near_misses=[_pm(phone, "id_number", 0)])
    assert any("near_miss" in str(k) for k in _kinds(hints))


def test_rust_and_python_agree():
    """The Python produce_hints is a parity-test-only oracle. Keep it honest.

    Both sides of the branch: the SUPPRESSED case and every KEPT case (same-type
    claimer, unclaimed span, merely-touching span).
    """
    pan = "6217000000000001"
    idn = "110101199003078888"
    cases = [
        # (label, text, accepted, near_misses, expect_hint)
        (
            "suppressed: other-type claimer",
            "卡号 6217000000000001",
            [_pm(pan, "bank_card", 3)],
            [_pm(pan, "credit_card", 3, conf=0.3)],
            False,
        ),
        (
            "kept: same-type claimer",
            "id 110101199003078888",
            [_pm(idn, "id_number", 3)],
            [_pm(idn, "id_number", 3, conf=0.3)],
            True,
        ),
        (
            "kept: unclaimed span",
            "id 110101199003078888",
            [],
            [_pm(idn, "id_number", 3, conf=0.3)],
            True,
        ),
        (
            "kept: merely touching",
            "13800138000110101199003078888",
            [_pm("13800138000", "phone", 0)],
            [_pm(idn, "id_number", 11, conf=0.3)],
            True,
        ),
    ]
    for label, text, accepted, nm, expect_hint in cases:
        rust = _core.produce_hints_l1(_to_core(accepted), text, _to_core(nm))
        py = produce_hints(accepted, text, near_misses=nm)
        assert rust == py, label
        assert any("near_miss" in k for k in _kinds(rust)) is expect_hint, label
