"""Golden: the built-in (type, lang) → faker-name association lives in `_core`.

Phase A of the v0.7.5 `_core` cutover exposed the association that USED to be
discovered by introspecting the registered Python `faker_reserved` callable's
`__name__`. Phase C (Task 11) made built-ins callable-less: the registry no
longer carries those callables, so the SSOT for the association is now the
`_core` table itself, cross-checked against the per-(type,lang) `register()`
calls in `specs/{zh,en,shared}.py` via the resolver `_builtin_faker_name_for`.

`_core.builtin_faker_name(type, lang)` and `_core.builtin_faker_names()` are the
read surface the callable-less built-in resolution dispatches through.
"""

import argus_redact._core as _core

from argus_redact.pure.replacer import _builtin_faker_name_for, _core_builtin_names
from argus_redact.specs import registry

# The 22 built-in (type, lang) pairs, transcribed from the per-lang `register()`
# calls in specs/{zh,en,shared}.py (the SSOT for which built-in faker each
# type+lang resolves to). The `_core` association is golden-locked against this
# list, and the resolver `_builtin_faker_name_for` is checked to agree.
_BUILTIN_PAIRS = {
    # zh
    ("phone", "zh"): "fake_phone_reserved",
    ("phone_landline", "zh"): "fake_phone_landline_reserved",
    ("id_number", "zh"): "fake_id_number_reserved",
    ("hk_id", "zh"): "fake_hkid_reserved",
    ("tw_id", "zh"): "fake_twid_reserved",
    ("macau_id", "zh"): "fake_macau_id_reserved",
    ("taiwan_arc", "zh"): "fake_taiwan_arc_reserved",
    ("bank_card", "zh"): "fake_bank_card_reserved",
    ("passport", "zh"): "fake_passport_reserved",
    ("license_plate", "zh"): "fake_license_plate_reserved",
    ("address", "zh"): "fake_address_reserved",
    ("date_of_birth", "zh"): "fake_date_of_birth_noise",
    ("person", "zh"): "fake_person_reserved",
    ("age", "zh"): "fake_age_noise",
    # en
    ("phone", "en"): "fake_phone_en_reserved",
    ("ssn", "en"): "fake_ssn_en_reserved",
    ("credit_card", "en"): "fake_credit_card_en_reserved",
    ("address", "en"): "fake_address_en_reserved",
    ("person", "en"): "fake_person_en_reserved",
    # shared
    ("email", "shared"): "fake_email_reserved",
    ("ip_address", "shared"): "fake_ip_reserved",
    ("mac_address", "shared"): "fake_mac_reserved",
}


def test_builtin_faker_name_matches_registry():
    """Every built-in (type, lang) resolves to its associated faker name, and
    each such type is actually registered for that lang (the SSOT pairing)."""
    n = 0
    for (type_, lang), expected in _BUILTIN_PAIRS.items():
        assert _core.builtin_faker_name(type_, lang) == expected, (type_, lang)
        # The (type, lang) must be a live registration so the association is not
        # pointing at a renamed/removed type.
        registered_langs = {td.lang for td in registry.lookup(type_)}
        assert lang in registered_langs, (type_, lang, registered_langs)
        n += 1
    assert n >= 20  # all built-in (type,lang) pairs covered


def test_resolver_agrees_with_core_association():
    """`_builtin_faker_name_for` (the lang-pref resolver) returns the associated
    faker name when its single detected lang is the type's registered lang."""
    for (type_, lang), expected in _BUILTIN_PAIRS.items():
        assert _builtin_faker_name_for(type_, [lang]) == expected, (type_, lang)


def test_builtin_faker_names_matches_pairs():
    assert set(_core.builtin_faker_names()) == set(_BUILTIN_PAIRS.values())
    # The module-level name-set used by `_build_type_info` is the same set.
    assert _core_builtin_names == set(_core.builtin_faker_names())


def test_builtin_faker_name_unknown_returns_none():
    assert _core.builtin_faker_name("nonexistent_type", "zh") is None
