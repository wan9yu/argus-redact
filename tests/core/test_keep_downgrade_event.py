"""Theme B Component 1: keep_downgraded structured event + residual-PII helper (pure)."""

from argus_redact._types import PatternMatch
from argus_redact.pure.replacer import (
    keep_downgraded_event,
    residual_personal_data,
)
from argus_redact.pure.security_events import KEEP_DOWNGRADED


def _pm(text, type_, start=0):
    return PatternMatch(
        text=text, type=type_, start=start, end=start + len(text), confidence=1.0, layer="L1"
    )


def test_keep_downgraded_event_none_when_no_keep():
    ents = [_pm("张三", "person")]
    assert keep_downgraded_event(ents, {"person": {"strategy": "pseudonym"}}) is None


def test_keep_downgraded_event_pii_free_detail():
    ents = [_pm("4111111111111111", "bank_card")]
    ev = keep_downgraded_event(ents, {"bank_card": {"strategy": "keep"}})
    assert ev["type"] == "security"
    assert ev["reason_code"] == KEEP_DOWNGRADED
    assert ev["count"] == 1
    assert ev["detail"] == "types: bank_card"
    assert "4111111111111111" not in ev["detail"]  # PII-free


def test_keep_downgraded_count_is_unique_texts_detail_is_sorted_types():
    ents = [
        _pm("4111111111111111", "bank_card"),
        _pm("4111111111111111", "bank_card", 20),  # duplicate text
        _pm("13800138000", "phone", 40),
    ]
    cfg = {"bank_card": {"strategy": "keep"}, "phone": {"strategy": "keep"}}
    ev = keep_downgraded_event(ents, cfg)
    assert ev["count"] == 2  # unique texts (dup card collapses)
    assert ev["detail"] == "types: bank_card, phone"  # sorted, deduped types


def test_residual_personal_data_true_for_pseudonym():
    ents = [_pm("张三", "person")]
    assert residual_personal_data(ents) is True


def test_residual_personal_data_true_for_mask():
    # mask writes surrogate->original into the returned key (e.g.
    # {'138****8000': '13800138000'}), and restore() recovers the original
    # from that key — a retained recovery key means the output is still
    # personal data under GDPR Art.4(5), regardless of how "irreversible"
    # the surrogate looks on its face.
    ents = [_pm("张三", "person")]
    assert residual_personal_data(ents) is True


def test_residual_personal_data_true_for_keep():
    # keep leaves the original value verbatim in the redacted output (no
    # key entry is even needed — the PII is right there), so this is also
    # residual personal data.
    ents = [_pm("I", "self_reference")]
    assert residual_personal_data(ents) is True


def test_residual_personal_data_false_for_empty():
    # Nothing detected -> nothing retained, nothing to recover.
    assert residual_personal_data([]) is False
