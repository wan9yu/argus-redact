"""``keep`` strategy must apply only to whitelisted self-reference pronouns.

H6: pre-fix, ``strategy="keep"`` wrote ``entity.text`` verbatim regardless of
type. If Layer-3 (Ollama) misclassified a sensitive value (e.g. SSN string)
as ``self_reference``, ``keep`` let the original PII flow into downstream_text.
v0.6.1+ downgrades to the type's default strategy with a SecurityWarning.
"""

from __future__ import annotations

import warnings

from argus_redact._types import PatternMatch
from argus_redact.pure.replacer import replace


def test_keep_strategy_should_preserve_english_self_reference_pronouns():
    """``keep`` is the documented behavior for legitimate first-person pronouns."""
    entities = [PatternMatch(text="I", type="self_reference", start=0, end=1, layer=1)]
    text, _key, _ = replace("I went home", entities)
    assert "I" in text  # kept verbatim


def test_keep_strategy_should_preserve_chinese_self_reference_pronouns():
    """Same for zh 我 / 我妈 / 我家人."""
    for txt in ("我", "我妈", "我家人", "我们"):
        entities = [PatternMatch(text=txt, type="self_reference", start=0, end=len(txt), layer=1)]
        out, _, _ = replace(f"{txt}去医院", entities)
        assert txt in out, f"legitimate self-reference {txt!r} stripped"


def test_keep_strategy_should_downgrade_with_a_warning_when_type_is_sensitive():
    """User config setting strategy='keep' on a sensitive type must NOT leak."""
    entities = [PatternMatch(text="110101199003074610", type="id_number", start=0, end=18, layer=1)]

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        text, key, _ = replace(
            "身份证110101199003074610",
            entities,
            config={"id_number": {"strategy": "keep"}},
            salt=42,
        )

        assert "110101199003074610" not in text, "keep strategy silently leaked PII"
        assert any(
            "keep" in str(w.message).lower() and "id_number" in str(w.message).lower()
            for w in captured
        ), "no SecurityWarning emitted when keep was downgraded"


def test_keep_strategy_should_still_redact_when_l3_misclassifies_ssn_as_self_reference():
    """If L3 assigns type=self_reference to a non-pronoun text (e.g. SSN), downgrade."""
    entities = [PatternMatch(text="123-45-6789", type="self_reference", start=12, end=23, layer=3)]
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        text, _key, _ = replace("patient SSN 123-45-6789", entities, salt=42)
        assert "123-45-6789" not in text, "L3 misclassification leaked SSN via keep — H6 regression"
        # Must have warned the user
        assert any("keep" in str(w.message).lower() for w in captured)


def test_security_warning_should_be_a_subclass_of_userwarning():
    """SecurityWarning must be a UserWarning subclass for default visibility."""
    from argus_redact import SecurityWarning

    assert issubclass(SecurityWarning, UserWarning)


def test_security_warning_should_be_importable_from_top_level():
    """SecurityWarning must be importable from the top-level package."""
    import argus_redact

    assert hasattr(argus_redact, "SecurityWarning")
