"""Unit tests for zh reserved-range fakers.

Each faker must:
1. Produce a value matching its reserved-range pattern
2. Pass the type's runtime validator (where applicable)
3. Be deterministic given the same inputs
"""

import re

import argus_redact._core as _core
from argus_redact.lang.shared.patterns import validate_luhn

_SALT = _core.resolve_salt(b"test-fakers-zh-reserved-salt!!")


def _fake(faker_name: str, value: str, type_: str) -> tuple[str, list]:
    return _core.generate_unique_fake(faker_name, value, type_, _SALT, set())


class TestFakePhoneReserved:
    def test_should_start_with_19999_prefix(self):
        result, _ = _fake("fake_phone_reserved", "13912345678", "phone")
        assert result.startswith("19999"), f"Expected 19999 prefix, got {result}"
        assert len(result) == 11, f"Expected 11 digits, got {len(result)}"
        assert result.isdigit()

    def test_should_be_deterministic_with_same_inputs(self):
        a, _ = _fake("fake_phone_reserved", "orig", "phone")
        b, _ = _fake("fake_phone_reserved", "orig", "phone")
        assert a == b


class TestFakeIdNumberReserved:
    def test_should_have_999_area_code(self):
        result, _ = _fake("fake_id_number_reserved", "110101199003077651", "id_number")
        assert result.startswith("999"), f"Expected 999 area code, got {result}"
        assert len(result) == 18

    def test_should_have_valid_gb11643_checksum(self):
        result, _ = _fake("fake_id_number_reserved", "orig", "id_number")
        weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check_chars = "10X98765432"
        body = result[:17]
        expected_check = check_chars[sum(int(body[i]) * weights[i] for i in range(17)) % 11]
        assert result[17] == expected_check


class TestFakeBankCardReserved:
    def test_should_have_999999_bin(self):
        result, _ = _fake("fake_bank_card_reserved", "6217001234567890", "bank_card")
        assert result.startswith("999999"), f"Expected 999999 BIN, got {result}"
        assert len(result) == 16

    def test_should_pass_luhn(self):
        result, _ = _fake("fake_bank_card_reserved", "orig", "bank_card")
        assert validate_luhn(result)


class TestFakePhoneLandlineReserved:
    def test_should_use_099_area_code(self):
        result, _ = _fake("fake_phone_landline_reserved", "010-12345678", "phone_landline")
        assert result.startswith("099-"), f"Expected 099- prefix, got {result}"


class TestFakePassportReserved:
    def test_should_use_99999_serial(self):
        result, _ = _fake("fake_passport_reserved", "E12345678", "passport")
        assert re.match(r"^[EG]99999\d{3}$", result), f"Got {result}"


class TestFakeLicensePlateReserved:
    def test_should_use_special_prefix_with_99999(self):
        result, _ = _fake("fake_license_plate_reserved", "京A12345", "license_plate")
        assert result[0] in ("测", "领"), f"Got {result}"
        assert "99999" in result


class TestFakeAddressReserved:
    def test_should_use_fictional_city(self):
        result, _ = _fake("fake_address_reserved", "北京市朝阳区建国路100号", "address")
        assert "滨海市" in result, f"Got {result}"


class TestFakePersonReserved:
    def test_should_use_canonical_fake_name(self):
        result, _ = _fake("fake_person_reserved", "王建国", "person")
        assert result in _core.reserved_person_names_zh(), (
            f"{result} not in canonical fake names"
        )
