"""Architecture drift tests for the pseudonym-llm profile.

Ensures that:
1. Every type listed in the pseudonym-llm profile has a faker_reserved on its PIITypeDef
2. Every faker_reserved produces values that match the corresponding scanner pattern
3. Removing a profile entry without removing the faker (or vice versa) fails CI
"""

import random
import re

from argus_redact.pure.reserved_range_scanner import _RESERVED_RANGE_PATTERNS
from argus_redact.specs import zh as _zh  # noqa: F401  ensure zh registry loaded
from argus_redact.specs.profiles import get_profile
from argus_redact.specs.registry import _REGISTRY

# Map zh PIITypeDef names → corresponding scanner-pattern keys. Only categorical
# types (with structured reserved ranges) are listed; numeric types like age and
# date_of_birth use range-noise fakers and have no scanner pattern by design.
_TYPE_TO_SCANNER = {
    "phone": "phone_zh",
    "phone_landline": "phone_landline_zh",
    "id_number": "id_number_zh",
    "bank_card": "bank_card_zh",
    "passport": "passport_zh",
    "license_plate": "license_plate_zh",
    "address": "address_zh",
    "person": "person_zh",
}

# Number of seeds per type — enough for coverage of the rng branches in each
# faker, while keeping the test fast.
_DRIFT_SEED_COUNT = 20


class TestRealisticDrift:
    def test_every_profile_type_should_have_faker_reserved(self):
        config = get_profile("pseudonym-llm")["config"]
        for type_name in config:
            # Try zh first, then shared
            typedef = _REGISTRY.get(("zh", type_name)) or _REGISTRY.get(("shared", type_name))
            assert typedef is not None, f"No PIITypeDef for {type_name}"
            assert typedef.faker_reserved is not None, (
                f"{type_name} is in pseudonym-llm profile but has no faker_reserved"
            )

    def test_every_faker_output_should_match_scanner_pattern(self):
        """If a faker_reserved is wired, its output for the categorical types
        should match the corresponding reserved-range scanner pattern.
        """
        config = get_profile("pseudonym-llm")["config"]
        for type_name in config:
            if type_name not in _TYPE_TO_SCANNER:
                continue  # numeric types skip
            typedef = _REGISTRY.get(("zh", type_name))
            assert typedef is not None
            faker = typedef.faker_reserved
            assert faker is not None

            scanner_key = _TYPE_TO_SCANNER[type_name]
            scanner_pattern = re.compile(_RESERVED_RANGE_PATTERNS[scanner_key])
            for seed in range(_DRIFT_SEED_COUNT):
                fake = faker("orig", random.Random(seed))
                assert scanner_pattern.search(fake), (
                    f"Faker for {type_name} (seed={seed}) produced {fake!r} "
                    f"which does not match scanner pattern "
                    f"{_RESERVED_RANGE_PATTERNS[scanner_key]}"
                )
