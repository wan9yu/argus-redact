"""Architectural guardrail: every reserved-range person name must declare aliases.

Without this test, adding a new entry to the zh/en reserved-name pool but
forgetting to add a transliteration to the aliases table would silently degrade
``restore()`` cross-language coverage.
"""

import argus_redact._core as _core


def test_every_zh_reserved_name_has_alias():
    names = _core.reserved_person_names_zh()
    aliases_dict = dict(_core.reserved_person_names_aliases_zh())
    missing = [n for n in names if not aliases_dict.get(n)]
    assert not missing, (
        f"Reserved zh names missing pinyin aliases: {missing}. "
        f"Add an entry to the zh aliases table in crates/argus-redact-core/data/fakers/zh.ron."
    )


def test_every_en_reserved_name_has_alias():
    names = _core.reserved_person_names_en()
    aliases_dict = dict(_core.reserved_person_names_aliases_en())
    missing = [n for n in names if not aliases_dict.get(n)]
    assert not missing, (
        f"Reserved en names missing zh transliteration aliases: {missing}. "
        f"Add an entry to the en aliases table in crates/argus-redact-core/data/fakers/en.ron."
    )


def test_every_zh_reserved_address_has_alias():
    cities = _core.reserved_cities_zh()
    addr_aliases_dict = dict(_core.reserved_addresses_zh_aliases())
    missing = [
        (city, district, street)
        for city, district, streets in cities
        for street in streets
        if (city, district, street) not in addr_aliases_dict
    ]
    assert not missing, (
        f"Reserved zh addresses missing en transliteration aliases: {missing}. "
        f"Add to the zh addresses aliases table in crates/argus-redact-core/data/fakers/zh.ron."
    )


def test_every_en_reserved_address_has_alias():
    addresses = _core.reserved_addresses_en()
    addr_aliases_dict = dict(_core.reserved_addresses_en_aliases())
    missing = [a for a in addresses if a not in addr_aliases_dict]
    assert not missing, f"Missing en address aliases: {missing}"
