"""Tests for en reserved-range fakers.

Each faker outputs values in officially-reserved or convention-reserved ranges:
- phone:       NANP 555-01XX (FCC 47 CFR § 52.15(f)(1)(ii))
- ssn:         999-XX-XXXX (SSA never assigns 9XX area)
- credit_card: 999999 BIN, Luhn-valid
- person:      John Doe / Jane Roe / Richard Roe etc.
- address:     fictional table (1313 Mockingbird Lane, etc.)
"""

import random
import re

from argus_redact.lang.shared.patterns import validate_luhn
from argus_redact.specs.fakers_en_reserved import (
    RESERVED_PERSON_NAMES_EN,
    fake_address_en_reserved,
    fake_credit_card_en_reserved,
    fake_person_en_reserved,
    fake_phone_en_reserved,
    fake_ssn_en_reserved,
)


class TestFakePhoneEnReserved:
    def test_should_use_555_01xx_format(self):
        result, _ = fake_phone_en_reserved("(415) 555-1234", random.Random(1))
        # Format: (555) 555-01XX
        assert re.match(r"^\(555\) 555-01\d{2}$", result), f"Got {result}"

    def test_should_be_deterministic(self):
        a, _ = fake_phone_en_reserved("orig", random.Random(7))
        b, _ = fake_phone_en_reserved("orig", random.Random(7))
        assert a == b


class TestFakeSsnEnReserved:
    def test_should_use_999_area(self):
        result, _ = fake_ssn_en_reserved("123-45-6789", random.Random(1))
        assert re.match(r"^999-\d{2}-\d{4}$", result), f"Got {result}"

    def test_should_be_deterministic(self):
        a, _ = fake_ssn_en_reserved("orig", random.Random(7))
        b, _ = fake_ssn_en_reserved("orig", random.Random(7))
        assert a == b


class TestFakeCreditCardEnReserved:
    def test_should_use_999999_bin_with_luhn(self):
        result, _ = fake_credit_card_en_reserved("4111111111111111", random.Random(1))
        assert result.startswith("999999"), f"Got {result}"
        assert len(result) == 16
        assert validate_luhn(result)


class TestFakePersonEnReserved:
    def test_should_use_canonical_fake_name(self):
        result, _ = fake_person_en_reserved("John Smith", random.Random(1))
        assert result in RESERVED_PERSON_NAMES_EN, f"Got {result}"


class TestFakeAddressEnReserved:
    def test_should_use_fictional_address(self):
        result, _ = fake_address_en_reserved("1234 Main St, Anytown, USA", random.Random(1))
        # All addresses use the固定虚构 table — Springfield USA is canonical
        assert "Springfield, USA" in result, f"Got {result}"
