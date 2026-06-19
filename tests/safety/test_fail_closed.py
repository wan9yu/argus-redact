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
