"""Fail-closed semantics — unknown lang / missing layers must not silently under-redact."""

import pytest

from argus_redact import redact


def test_unknown_lang_raises():
    with pytest.raises(ValueError, match="Unknown language"):
        redact("电话13800138000", lang="cn", mode="fast", salt=42)


def test_known_lang_still_works():
    out, key = redact("电话13800138000", lang="zh", mode="fast", salt=42)
    assert len(key) >= 1


from argus_redact import LayerUnavailableError


def test_ner_mode_no_model_raises(monkeypatch):
    import argus_redact.glue.redact as r
    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang: [])
    with pytest.raises(LayerUnavailableError):
        redact("Contact John Smith", lang="en", mode="ner", salt=42)


def test_auto_mode_no_model_warns_not_raises(monkeypatch):
    import argus_redact.glue.redact as r
    from argus_redact import SecurityWarning
    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang: [])
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)
    with pytest.warns(SecurityWarning):
        out, key = redact("Contact John Smith", lang="en", mode="auto", salt=42)
    assert isinstance(out, str)


def test_auto_mode_strict_raises(monkeypatch):
    import argus_redact.glue.redact as r
    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang: [])
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)
    with pytest.raises(LayerUnavailableError):
        redact("Contact John Smith", lang="en", mode="auto", salt=42, strict=True)


# Instruction-intent input ("Please tell me about myself") triggers
# should_skip_ner — the availability check must still fire even though the L2
# DETECTION run is skipped. The existing fail-closed tests above all use
# "Contact John Smith" (neutral intent), which never hits the skip path, so the
# unconditional-availability contract was untested.


def test_ner_no_model_raises_even_for_instruction_intent(monkeypatch):
    import argus_redact.glue.redact as r
    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang: [])
    with pytest.raises(LayerUnavailableError):
        redact("Please tell me about myself", mode="ner", lang="en", salt=42)


def test_auto_no_model_warns_even_for_instruction_intent(monkeypatch):
    import argus_redact.glue.redact as r
    from argus_redact import SecurityWarning
    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang: [])
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)
    # Match the no-model degradation message specifically — a bare SecurityWarning
    # assertion would be satisfied by the unrelated low-entropy-salt warning.
    with pytest.warns(SecurityWarning, match="no NER model available"):
        redact("Please tell me about myself", mode="auto", lang="en", salt=42)


def test_auto_strict_no_model_raises_even_for_instruction_intent(monkeypatch):
    import argus_redact.glue.redact as r
    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang: [])
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)
    with pytest.raises(LayerUnavailableError):
        redact("Please tell me about myself", mode="auto", lang="en", strict=True, salt=42)


def test_low_entropy_int_salt_warns():
    from argus_redact import SecurityWarning
    with pytest.warns(SecurityWarning, match="low-entropy salt"):
        redact("电话13800138000", lang="zh", mode="fast", salt=42)


def test_strong_salt_no_warning(recwarn):
    import argus_redact
    redact("电话13800138000", lang="zh", mode="fast", salt=b"\x00" * 32)
    assert not any(
        issubclass(w.category, argus_redact.SecurityWarning) for w in recwarn
    )
