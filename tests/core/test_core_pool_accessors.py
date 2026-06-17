"""Pool-snapshot golden: every Phase-D-imported pool has a _core accessor
that returns data in the exact same order as the Python pool constant.

Bit-identity contract: the RON was transcribed verbatim from the Python
pools; any reorder silently breaks faker output because choice_index() picks
by position. These assertions are the order-exact equality gate.
"""

import argus_redact._core as _core
from argus_redact.specs import fakers_zh_reserved as zh
from argus_redact.specs import fakers_en_reserved as en
from argus_redact.specs import fakers_shared_reserved as sh


# ── zh pools ────────────────────────────────────────────────────────────────


def test_zh_reserved_person_names_match():
    assert list(_core.reserved_person_names_zh()) == list(zh.RESERVED_PERSON_NAMES)


def test_zh_reserved_person_names_aliases_match():
    # Returned as Vec<(str, list[str])> — order-preserving list of (name, aliases) pairs.
    rust_aliases = dict(_core.reserved_person_names_aliases_zh())
    py_aliases = dict(zh.RESERVED_PERSON_NAMES_ALIASES)
    assert rust_aliases == py_aliases
    # Also assert insertion order matches (Python 3.7+ dicts preserve order).
    assert [k for k, _ in _core.reserved_person_names_aliases_zh()] == list(zh.RESERVED_PERSON_NAMES_ALIASES)


def test_zh_reserved_cities_match():
    rust_cities = list(_core.reserved_cities_zh())
    py_cities = list(zh.RESERVED_CITIES)
    # Python: tuple of (city, district, tuple_of_streets)
    # Rust: Vec<(String, String, Vec<String>)>
    assert len(rust_cities) == len(py_cities)
    for (rc, rd, rstreets), (pc, pd, pstreets) in zip(rust_cities, py_cities):
        assert rc == pc
        assert rd == pd
        assert list(rstreets) == list(pstreets)


def test_zh_reserved_addresses_zh_aliases_match():
    # RESERVED_ADDRESSES_ZH_ALIASES: dict[tuple[str,str,str], list[str]]
    # Returned as Vec<((str,str,str), list[str])> — order-preserving.
    rust_aliases = _core.reserved_addresses_zh_aliases()
    rust_dict = {tuple(k): list(v) for k, v in rust_aliases}
    py_dict = {k: list(v) for k, v in zh.RESERVED_ADDRESSES_ZH_ALIASES.items()}
    assert rust_dict == py_dict
    # Order check.
    rust_keys = [tuple(k) for k, _ in rust_aliases]
    py_keys = list(zh.RESERVED_ADDRESSES_ZH_ALIASES.keys())
    assert rust_keys == py_keys


def test_zh_passport_prefixes_match():
    assert list(_core.passport_prefixes_zh()) == list(zh.PASSPORT_PREFIXES)


def test_zh_plate_special_prefixes_match():
    assert list(_core.plate_special_prefixes_zh()) == list(zh.PLATE_SPECIAL_PREFIXES)


def test_zh_hkid_reserved_letter_match():
    assert _core.hkid_reserved_letter() == zh.HKID_RESERVED_LETTER


def test_zh_twid_reserved_letter_match():
    assert _core.twid_reserved_letter() == zh.TWID_RESERVED_LETTER


def test_zh_macau_reserved_lead_match():
    assert _core.macau_reserved_lead() == zh.MACAU_RESERVED_LEAD


def test_zh_twarc_reserved_prefix_match():
    assert _core.twarc_reserved_prefix() == zh.TWARC_RESERVED_PREFIX


# ── en pools ────────────────────────────────────────────────────────────────


def test_en_reserved_person_names_match():
    assert list(_core.reserved_person_names_en()) == list(en.RESERVED_PERSON_NAMES_EN)


def test_en_reserved_person_names_aliases_match():
    rust_aliases = dict(_core.reserved_person_names_aliases_en())
    py_aliases = dict(en.RESERVED_PERSON_NAMES_EN_ALIASES)
    assert rust_aliases == py_aliases
    assert [k for k, _ in _core.reserved_person_names_aliases_en()] == list(en.RESERVED_PERSON_NAMES_EN_ALIASES)


def test_en_reserved_addresses_match():
    assert list(_core.reserved_addresses_en()) == list(en.RESERVED_ADDRESSES_EN)


def test_en_reserved_addresses_aliases_match():
    rust_aliases = _core.reserved_addresses_en_aliases()
    rust_dict = {k: list(v) for k, v in rust_aliases}
    py_dict = {k: list(v) for k, v in en.RESERVED_ADDRESSES_EN_ALIASES.items()}
    assert rust_dict == py_dict
    rust_keys = [k for k, _ in rust_aliases]
    py_keys = list(en.RESERVED_ADDRESSES_EN_ALIASES.keys())
    assert rust_keys == py_keys


# ── shared pools ─────────────────────────────────────────────────────────────


def test_shared_rfc2606_domains_match():
    assert list(_core.rfc2606_domains()) == list(sh.RFC2606_DOMAINS)


def test_shared_rfc5737_prefixes_match():
    assert list(_core.rfc5737_prefixes()) == list(sh.RFC5737_PREFIXES)


def test_shared_rfc7042_mac_prefix_match():
    assert _core.rfc7042_mac_prefix() == sh.RFC7042_MAC_PREFIX
