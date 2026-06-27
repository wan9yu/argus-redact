from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm
from argus_redact.glue.redact import _detect


def test_pre_detected_matches_internal_detect():
    text = "电话13800138000"
    ents, *_ = _detect(text, lang="zh", mode="fast", names=None, types=None, types_exclude=None)
    a = redact_pseudonym_llm(text, salt=42, lang="zh", mode="fast", _polluted_input_ok=True)
    b = redact_pseudonym_llm(text, salt=42, lang="zh", mode="fast", _polluted_input_ok=True,
                             _pre_detected=ents)
    assert a.downstream_text == b.downstream_text
    assert a.audit_text == b.audit_text
    assert a.key == b.key


def test_pre_detected_empty_redacts_nothing():
    text = "电话13800138000"
    b = redact_pseudonym_llm(text, salt=42, lang="zh", mode="fast", _polluted_input_ok=True,
                             _pre_detected=[])
    assert b.downstream_text == text
