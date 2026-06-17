"""Architecture drift tests for the pseudonym-llm profile.

Ensures that:
1. Every type listed in the pseudonym-llm profile has a RESOLVABLE faker —
   built-in types resolve via the `_core` (type, lang)→faker_name association
   (v0.7.5: built-ins are callable-less); a custom type keeps its `faker_reserved`.
2. Every built-in faker produces values that match the corresponding scanner
   pattern (driven through `_core.generate_unique_fake` by faker name).
3. Removing a profile entry without removing the faker (or vice versa) fails CI.
"""

import re

import argus_redact._core as _core

_RESERVED_RANGE_PATTERNS = dict(_core.reserved_range_patterns())
from argus_redact.specs import en as _en  # noqa: F401  ensure en registry loaded
from argus_redact.specs import shared as _shared  # noqa: F401
from argus_redact.specs import zh as _zh  # noqa: F401
from argus_redact.specs.profiles import get_profile
from argus_redact.specs.registry import lookup

_BUILTIN_FAKER_NAMES = frozenset(_core.builtin_faker_names())


def _find_typedef(name: str, *langs: str):
    """Return the first PIITypeDef in `langs` order whose name matches."""
    by_lang = {td.lang: td for td in lookup(name)}
    for lang in langs:
        if lang in by_lang:
            return by_lang[lang]
    return None


# Map (type_name, lang) → scanner-pattern key. Only categorical types are listed;
# numeric types (age, date_of_birth) and NER-only types (en/person in fast mode)
# have noise-based or no scanner patterns and skip this drift check.
_TYPE_LANG_TO_SCANNER = {
    # zh
    ("phone", "zh"): "phone_zh",
    ("phone_landline", "zh"): "phone_landline_zh",
    ("id_number", "zh"): "id_number_zh",
    ("bank_card", "zh"): "bank_card_zh",
    ("passport", "zh"): "passport_zh",
    ("hk_id", "zh"): "hk_id_zh",
    ("tw_id", "zh"): "tw_id_zh",
    ("macau_id", "zh"): "macau_id_zh",
    ("taiwan_arc", "zh"): "taiwan_arc_zh",
    ("license_plate", "zh"): "license_plate_zh",
    ("address", "zh"): "address_zh",
    ("person", "zh"): "person_zh",
    # en
    ("phone", "en"): "phone_en",
    ("ssn", "en"): "ssn_en",
    ("credit_card", "en"): "credit_card_en",
    ("person", "en"): "person_en",
    ("address", "en"): "address_en",
    # shared (RFC documentation ranges)
    ("email", "shared"): "email_shared",
    ("ip_address", "shared"): "ipv4_shared",  # default IPv4 path; v6 covered separately
    ("mac_address", "shared"): "mac_shared",
}

_DRIFT_SEED_COUNT = 20


class TestRealisticDrift:
    def test_every_profile_type_should_have_resolvable_faker(self):
        """Every pseudonym-llm profile type must resolve to a faker. Built-ins
        resolve callable-less via the `_core` association; a custom type keeps a
        real `faker_reserved`. (v0.7.5: built-ins dropped `faker_reserved=`.)"""
        config = get_profile("pseudonym-llm")["config"]
        for type_name in config:
            typedef = _find_typedef(type_name, "zh", "en", "shared")
            assert typedef is not None, f"No PIITypeDef for {type_name}"
            builtin_name = _core.builtin_faker_name(typedef.name, typedef.lang)
            assert builtin_name is not None or typedef.faker_reserved is not None, (
                f"{type_name} is in pseudonym-llm profile but has neither a built-in "
                f"_core faker association nor a custom faker_reserved"
            )

    def test_scanner_keys_referenced_by_drift_table_must_exist(self):
        """If _TYPE_LANG_TO_SCANNER points at a renamed/missing scanner key, fail loudly."""
        missing = set(_TYPE_LANG_TO_SCANNER.values()) - set(_RESERVED_RANGE_PATTERNS)
        assert not missing, (
            f"Scanner keys missing from _core.reserved_range_patterns(): {missing}. "
            f"Either add the patterns to the Rust reserved_range module or remove "
            f"these entries from _TYPE_LANG_TO_SCANNER."
        )

    def test_every_faker_output_should_match_scanner_pattern(self):
        """For each (type, lang) with a scanner pattern, the built-in faker (resolved
        by name via the `_core` association and run through `_core.generate_unique_fake`)
        must emit values matching the scanner pattern."""
        for (type_name, lang), scanner_key in _TYPE_LANG_TO_SCANNER.items():
            typedef = _find_typedef(type_name, lang)
            assert typedef is not None, f"No PIITypeDef for ({lang}, {type_name})"
            faker_name = _core.builtin_faker_name(typedef.name, typedef.lang)
            assert faker_name is not None, (
                f"({lang}, {type_name}) has no built-in faker association in _core"
            )
            assert faker_name in _BUILTIN_FAKER_NAMES, faker_name

            scanner_pattern = re.compile(_RESERVED_RANGE_PATTERNS[scanner_key])
            for seed in range(_DRIFT_SEED_COUNT):
                salt = _core.resolve_salt(seed)
                fake, _aliases = _core.generate_unique_fake(
                    faker_name,
                    value="orig",
                    type_=type_name,
                    salt=salt,
                    used=set(),
                )
                assert scanner_pattern.search(fake), (
                    f"Faker for ({lang}, {type_name}) salt={seed} produced {fake!r} "
                    f"which does not match scanner {scanner_key}: {_RESERVED_RANGE_PATTERNS[scanner_key]}"
                )

    def test_ipv6_faker_should_match_v6_scanner(self):
        """ip_address faker switches on input shape; v6 path uses 2001:db8 prefix."""
        faker_name = _core.builtin_faker_name("ip_address", "shared")
        assert faker_name is not None

        v6_pattern = re.compile(_RESERVED_RANGE_PATTERNS["ipv6_shared"])
        for seed in range(_DRIFT_SEED_COUNT):
            salt = _core.resolve_salt(seed)
            fake, _ = _core.generate_unique_fake(
                faker_name,
                value="fe80::1",
                type_="ip_address",
                salt=salt,
                used=set(),
            )
            assert v6_pattern.search(fake), f"v6 faker salt={seed} → {fake!r}"
