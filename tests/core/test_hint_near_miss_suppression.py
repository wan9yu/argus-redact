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


def test_rust_and_python_agree():
    """The Python produce_hints is a parity-test-only oracle. Keep it honest."""
    text = "卡号 6217000000000001"
    pan = "6217000000000001"
    accepted = [_pm(pan, "bank_card", 3)]
    nm = [_pm(pan, "credit_card", 3, conf=0.3)]
    rust = _core.produce_hints_l1(_to_core(accepted), text, _to_core(nm))
    py = produce_hints(accepted, text, near_misses=nm)
    assert rust == py
    assert not any("near_miss" in k for k in _kinds(rust))
