"""Fail-closed semantics — unknown lang / missing layers must not silently under-redact."""

import pytest

from argus_redact import LayerUnavailableError, redact


def test_redact_should_raise_value_error_when_language_is_unknown():
    with pytest.raises(ValueError, match="Unknown language"):
        redact("电话13800138000", lang="cn", mode="fast", salt=42)


def test_redact_should_succeed_when_language_is_known():
    out, key = redact("电话13800138000", lang="zh", mode="fast", salt=42)
    assert len(key) >= 1


def test_redact_should_raise_layer_unavailable_when_ner_mode_has_no_model(monkeypatch):
    import argus_redact.glue.redact as r

    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang, **_kw: [])
    with pytest.raises(LayerUnavailableError):
        redact("Contact John Smith", lang="en", mode="ner", salt=42)


def test_redact_should_warn_when_auto_mode_has_no_model(monkeypatch):
    import argus_redact.glue.redact as r
    from argus_redact import SecurityWarning

    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang, **_kw: [])
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)
    with pytest.warns(SecurityWarning):
        out, key = redact("Contact John Smith", lang="en", mode="auto", salt=42)
    assert isinstance(out, str)


def test_redact_should_raise_when_strict_auto_mode_has_no_model(monkeypatch):
    import argus_redact.glue.redact as r

    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang, **_kw: [])
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)
    with pytest.raises(LayerUnavailableError):
        redact("Contact John Smith", lang="en", mode="auto", salt=42, strict=True)


# Instruction-intent input ("Please tell me about myself") triggers
# should_skip_ner — the availability check must still fire even though the L2
# DETECTION run is skipped. The existing fail-closed tests above all use
# "Contact John Smith" (neutral intent), which never hits the skip path, so the
# unconditional-availability contract was untested.


def test_redact_should_raise_layer_unavailable_when_ner_has_no_model_for_instruction_intent(
    monkeypatch,
):
    import argus_redact.glue.redact as r

    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang, **_kw: [])
    with pytest.raises(LayerUnavailableError):
        redact("Please tell me about myself", mode="ner", lang="en", salt=42)


def test_redact_should_warn_when_auto_mode_has_no_model_for_instruction_intent(monkeypatch):
    import argus_redact.glue.redact as r
    from argus_redact import SecurityWarning

    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang, **_kw: [])
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)
    # Match the no-model degradation message specifically — a bare SecurityWarning
    # assertion would be satisfied by the unrelated low-entropy-salt warning.
    with pytest.warns(SecurityWarning, match="no NER model available"):
        redact("Please tell me about myself", mode="auto", lang="en", salt=42)


def test_redact_should_raise_when_strict_auto_mode_has_no_model_for_instruction_intent(
    monkeypatch,
):
    import argus_redact.glue.redact as r

    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang, **_kw: [])
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)
    with pytest.raises(LayerUnavailableError):
        redact("Please tell me about myself", mode="auto", lang="en", strict=True, salt=42)


def test_redact_should_warn_when_salt_has_low_entropy():
    from argus_redact import SecurityWarning

    with pytest.warns(SecurityWarning, match="low-entropy salt"):
        redact("电话13800138000", lang="zh", mode="fast", salt=42)


def test_redact_should_not_warn_when_salt_is_strong(recwarn):
    import argus_redact

    redact("电话13800138000", lang="zh", mode="fast", salt=b"\x00" * 32)
    assert not any(issubclass(w.category, argus_redact.SecurityWarning) for w in recwarn)


# `_get_ner_adapters` catches (ModuleNotFoundError, ImportError, OSError) around
# the adapter load — OSError on purpose, because it is what the documented
# install path actually raises: `pip install argus-redact[en]` installs spaCy
# but not the model, and `spacy.load("en_core_web_sm")` then raises OSError
# ("[E050] Can't find model"), not an ImportError subclass. The tests above all
# monkeypatch `_get_ner_adapters` itself away, so none of them ever runs the
# real function's except clause — an OSError raised INSIDE load() used to
# escape uncaught (a hard crash / 500 over HTTP) instead of degrading like a
# missing package does.


def test_get_ner_adapters_should_catch_oserror_when_model_load_fails(monkeypatch):
    """A real OSError raised inside adapter.load() (the documented "model not
    downloaded" failure) must be swallowed by `_get_ner_adapters`'s except
    clause and recorded in `unavailable` — not escape as an uncaught OSError."""
    import argus_redact.glue.redact as r
    from argus_redact.lang.en.ner_adapter import SpaCyAdapter

    def _raise_model_not_found(self):
        raise OSError("[E050] Can't find model 'en_core_web_sm'")

    monkeypatch.setattr(SpaCyAdapter, "load", _raise_model_not_found)

    unavailable: list[str] = []
    adapters = r._get_ner_adapters("en", unavailable=unavailable)
    assert adapters == []
    assert unavailable == ["en"]


def test_redact_should_raise_layer_unavailable_when_ner_load_raises_oserror(monkeypatch):
    """mode='ner' with only a load-time OSError available must surface the
    documented LayerUnavailableError, not the raw OSError from spaCy."""
    from argus_redact.lang.en.ner_adapter import SpaCyAdapter

    monkeypatch.setattr(
        SpaCyAdapter,
        "load",
        lambda self: (_ for _ in ()).throw(OSError("[E050] Can't find model 'en_core_web_sm'")),
    )
    with pytest.raises(LayerUnavailableError):
        redact("Contact John Smith", lang="en", mode="ner", salt=42)


def test_redact_should_warn_when_auto_mode_load_raises_oserror(monkeypatch):
    """mode='auto' with only a load-time OSError available must degrade (warn,
    keep going with L1-only) exactly like the "no package installed" case."""
    import argus_redact.glue.redact as r
    from argus_redact import SecurityWarning
    from argus_redact.lang.en.ner_adapter import SpaCyAdapter

    monkeypatch.setattr(
        SpaCyAdapter,
        "load",
        lambda self: (_ for _ in ()).throw(OSError("[E050] Can't find model 'en_core_web_sm'")),
    )
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)
    with pytest.warns(SecurityWarning, match="no NER model available"):
        out, key = redact("Contact John Smith", lang="en", mode="auto", salt=42)
    assert isinstance(out, str)


# A `lang=['zh', 'en']` call where the zh adapter loads but the en one fails
# (the same load()-raises-OSError seam as above) is a PARTIAL multi-language
# load: the layer ran, just not for every requested language. Untested before
# this — every other fail-closed test above uses a single lang, so the
# unavailable_langs-non-empty-but-adapters-non-empty branch (":~529-556" in
# glue/redact.py) never actually ran.


def _mock_zh_adapter_succeeds(monkeypatch):
    """zh's HanLPAdapter.load()/.detect() replaced with no-ops so the "succeeding"
    side of a partial load doesn't require the real hanlp model installed."""
    from argus_redact.lang.zh.ner_adapter import HanLPAdapter

    monkeypatch.setattr(HanLPAdapter, "load", lambda self: None)
    monkeypatch.setattr(HanLPAdapter, "detect", lambda self, text: [])


def _mock_en_adapter_fails(monkeypatch):
    from argus_redact.lang.en.ner_adapter import SpaCyAdapter

    monkeypatch.setattr(
        SpaCyAdapter,
        "load",
        lambda self: (_ for _ in ()).throw(OSError("[E050] Can't find model 'en_core_web_sm'")),
    )


def test_redact_should_mark_layer_partial_and_warn_when_multilang_ner_load_is_partial(
    monkeypatch,
):
    import argus_redact.glue.redact as r
    from argus_redact import SecurityWarning

    _mock_zh_adapter_succeeds(monkeypatch)
    _mock_en_adapter_fails(monkeypatch)
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)

    # Needs pii_count > 0 (the phone number) so should_skip_ner is False and
    # the layer actually runs instead of staying "skipped" despite the warning.
    text = "Contact John Smith, 电话13800138000"
    with pytest.warns(SecurityWarning, match=r"no NER model available for language\(s\): en"):
        result = redact(text, lang=["zh", "en"], mode="auto", salt=b"\x00" * 32, report=True)
    assert result.stats["layer_2_status"] == "partial"


def test_redact_should_raise_when_strict_multilang_ner_load_is_partial(monkeypatch):
    import argus_redact.glue.redact as r

    _mock_zh_adapter_succeeds(monkeypatch)
    _mock_en_adapter_fails(monkeypatch)
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: None)

    text = "Contact John Smith, 电话13800138000"
    with pytest.raises(LayerUnavailableError, match="en"):
        redact(text, lang=["zh", "en"], mode="auto", salt=b"\x00" * 32, strict=True)
