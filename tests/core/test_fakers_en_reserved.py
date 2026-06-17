"""Tests for en reserved-range fakers.

Each faker outputs values in officially-reserved or convention-reserved ranges:
- phone:       NANP 555-01XX (FCC 47 CFR § 52.15(f)(1)(ii))
- ssn:         999-XX-XXXX (SSA never assigns 9XX area)
- credit_card: 999999 BIN, Luhn-valid
- person:      John Doe / Jane Roe / Richard Roe etc.
- address:     fictional table (1313 Mockingbird Lane, etc.)
"""

import re

import argus_redact._core as _core
from argus_redact.lang.shared.patterns import validate_luhn

_SALT = _core.resolve_salt(b"test-fakers-en-reserved-salt!!")


def _fake(faker_name: str, value: str, type_: str) -> tuple[str, list]:
    return _core.generate_unique_fake(faker_name, value, type_, _SALT, set())


class TestFakePhoneEnReserved:
    def test_should_use_555_01xx_format(self):
        result, _ = _fake("fake_phone_en_reserved", "(415) 555-1234", "phone")
        # Format: (555) 555-01XX
        assert re.match(r"^\(555\) 555-01\d{2}$", result), f"Got {result}"

    def test_should_be_deterministic(self):
        a, _ = _fake("fake_phone_en_reserved", "orig", "phone")
        b, _ = _fake("fake_phone_en_reserved", "orig", "phone")
        assert a == b


class TestFakeSsnEnReserved:
    def test_should_use_999_area(self):
        result, _ = _fake("fake_ssn_en_reserved", "123-45-6789", "ssn")
        assert re.match(r"^999-\d{2}-\d{4}$", result), f"Got {result}"

    def test_should_be_deterministic(self):
        a, _ = _fake("fake_ssn_en_reserved", "orig", "ssn")
        b, _ = _fake("fake_ssn_en_reserved", "orig", "ssn")
        assert a == b


class TestFakeCreditCardEnReserved:
    def test_should_use_999999_bin_with_luhn(self):
        result, _ = _fake("fake_credit_card_en_reserved", "4111111111111111", "credit_card")
        assert result.startswith("999999"), f"Got {result}"
        assert len(result) == 16
        assert validate_luhn(result)


class TestFakePersonEnReserved:
    def test_should_use_canonical_fake_name(self):
        result, _ = _fake("fake_person_en_reserved", "John Smith", "person")
        assert result in _core.reserved_person_names_en(), f"Got {result}"


class TestFakeAddressEnReserved:
    def test_should_use_fictional_address(self):
        result, _ = _fake("fake_address_en_reserved", "1234 Main St, Anytown, USA", "address")
        # Must be one of the fictional table entries
        assert result in _core.reserved_addresses_en(), f"Got {result}"
