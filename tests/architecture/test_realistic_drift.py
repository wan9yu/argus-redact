"""Architecture drift tests for the pseudonym-llm profile.

Ensures that:
1. Every type listed in the pseudonym-llm profile has a faker_reserved on its PIITypeDef
2. Every faker_reserved produces values that match the corresponding scanner pattern
3. Removing a profile entry without removing the faker (or vice versa) fails CI
"""

import random
import re

from argus_redact.pure.reserved_range_scanner import _RESERVED_RANGE_PATTERNS
from argus_redact.specs import en as _en  # noqa: F401  ensure en registry loaded
from argus_redact.specs import shared as _shared  # noqa: F401
from argus_redact.specs import zh as _zh  # noqa: F401
from argus_redact.specs.profiles import get_profile
from argus_redact.specs.registry import lookup


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
    def test_every_profile_type_should_have_faker_reserved(self):
        config = get_profile("pseudonym-llm")["config"]
        for type_name in config:
            typedef = _find_typedef(type_name, "zh", "en", "shared")
            assert typedef is not None, f"No PIITypeDef for {type_name}"
            assert typedef.faker_reserved is not None, (
                f"{type_name} is in pseudonym-llm profile but has no faker_reserved"
            )

    def test_scanner_keys_referenced_by_drift_table_must_exist(self):
        """If _TYPE_LANG_TO_SCANNER points at a renamed/missing scanner key, fail loudly."""
        missing = set(_TYPE_LANG_TO_SCANNER.values()) - set(_RESERVED_RANGE_PATTERNS)
        assert not missing, (
            f"Scanner keys missing from _RESERVED_RANGE_PATTERNS: {missing}. "
            f"Either add the patterns to reserved_range_scanner.py or remove these "
            f"entries from _TYPE_LANG_TO_SCANNER."
        )

    def test_every_faker_output_should_match_scanner_pattern(self):
        """For each (type, lang) with a scanner pattern, faker output must match it."""
        for (type_name, lang), scanner_key in _TYPE_LANG_TO_SCANNER.items():
            typedef = _find_typedef(type_name, lang)
            assert typedef is not None, f"No PIITypeDef for ({lang}, {type_name})"
            faker = typedef.faker_reserved
            assert faker is not None, f"({lang}, {type_name}) has no faker_reserved"

            scanner_pattern = re.compile(_RESERVED_RANGE_PATTERNS[scanner_key])
            for seed in range(_DRIFT_SEED_COUNT):
                fake, _aliases = faker("orig", random.Random(seed))
                assert scanner_pattern.search(fake), (
                    f"Faker for ({lang}, {type_name}) seed={seed} produced {fake!r} "
                    f"which does not match scanner {scanner_key}: {_RESERVED_RANGE_PATTERNS[scanner_key]}"
                )

    def test_ipv6_faker_should_match_v6_scanner(self):
        """ip_address faker switches on input shape; v6 path uses 2001:db8 prefix."""
        from argus_redact.specs.fakers_shared_reserved import fake_ip_reserved

        v6_pattern = re.compile(_RESERVED_RANGE_PATTERNS["ipv6_shared"])
        for seed in range(_DRIFT_SEED_COUNT):
            fake, _ = fake_ip_reserved("fe80::1", random.Random(seed))
            assert v6_pattern.search(fake), f"v6 faker seed={seed} → {fake!r}"
