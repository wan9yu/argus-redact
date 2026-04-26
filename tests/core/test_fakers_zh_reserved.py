"""Unit tests for zh reserved-range fakers.

Each faker must:
1. Produce a value matching its reserved-range pattern
2. Pass the type's runtime validator (where applicable)
3. Be deterministic given the same RNG seed
"""

import random
import re

from argus_redact.specs.fakers_zh_reserved import (
    RESERVED_PERSON_NAMES,
    fake_address_reserved,
    fake_bank_card_reserved,
    fake_id_number_reserved,
    fake_license_plate_reserved,
    fake_passport_reserved,
    fake_person_reserved,
    fake_phone_landline_reserved,
    fake_phone_reserved,
)


class TestFakePhoneReserved:
    def test_should_start_with_19999_prefix(self):
        rng = random.Random(42)
        result = fake_phone_reserved("13912345678", rng)
        assert result.startswith("19999"), f"Expected 19999 prefix, got {result}"
        assert len(result) == 11, f"Expected 11 digits, got {len(result)}"
        assert result.isdigit()

    def test_should_be_deterministic_with_same_seed(self):
        a = fake_phone_reserved("orig", random.Random(7))
        b = fake_phone_reserved("orig", random.Random(7))
        assert a == b


class TestFakeIdNumberReserved:
    def test_should_have_999_area_code(self):
        rng = random.Random(42)
        result = fake_id_number_reserved("110101199003077651", rng)
        assert result.startswith("999"), f"Expected 999 area code, got {result}"
        assert len(result) == 18

    def test_should_have_valid_gb11643_checksum(self):
        result = fake_id_number_reserved("orig", random.Random(1))
        weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check_chars = "10X98765432"
        body = result[:17]
        expected_check = check_chars[sum(int(body[i]) * weights[i] for i in range(17)) % 11]
        assert result[17] == expected_check


class TestFakeBankCardReserved:
    def test_should_have_999999_bin(self):
        rng = random.Random(42)
        result = fake_bank_card_reserved("6217001234567890", rng)
        assert result.startswith("999999"), f"Expected 999999 BIN, got {result}"
        assert len(result) == 16

    def test_should_pass_luhn(self):
        result = fake_bank_card_reserved("orig", random.Random(1))
        digits = [int(d) for d in result]
        odd_sum = sum(digits[-1::-2])
        even_sum = sum(d * 2 - 9 if d * 2 > 9 else d * 2 for d in digits[-2::-2])
        assert (odd_sum + even_sum) % 10 == 0


class TestFakePhoneLandlineReserved:
    def test_should_use_099_area_code(self):
        result = fake_phone_landline_reserved("010-12345678", random.Random(1))
        assert result.startswith("099-"), f"Expected 099- prefix, got {result}"


class TestFakePassportReserved:
    def test_should_use_99999_serial(self):
        result = fake_passport_reserved("E12345678", random.Random(1))
        assert re.match(r"^[EG]99999\d{3}$", result), f"Got {result}"


class TestFakeLicensePlateReserved:
    def test_should_use_special_prefix_with_99999(self):
        result = fake_license_plate_reserved("京A12345", random.Random(1))
        assert result[0] in ("测", "领"), f"Got {result}"
        assert "99999" in result


class TestFakeAddressReserved:
    def test_should_use_fictional_city(self):
        result = fake_address_reserved("北京市朝阳区建国路100号", random.Random(1))
        assert "滨海市" in result, f"Got {result}"


class TestFakePersonReserved:
    def test_should_use_canonical_fake_name(self):
        result = fake_person_reserved("王建国", random.Random(1))
        assert result in RESERVED_PERSON_NAMES, f"{result} not in canonical fake names"
