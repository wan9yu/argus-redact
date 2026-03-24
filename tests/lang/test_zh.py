"""Tests for Chinese regex patterns."""

import pytest

from argus_redact.pure.patterns import match_patterns
from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS


@pytest.fixture
def all_patterns():
    return ZH_PATTERNS + SHARED_PATTERNS


class TestChinesePhone:
    """Chinese mobile and landline phone numbers."""

    def test_mobile_standard(self, all_patterns):
        results = match_patterns("手机号13812345678", all_patterns)
        assert len(results) == 1
        assert results[0].text == "13812345678"
        assert results[0].type == "phone"

    def test_mobile_with_country_code(self, all_patterns):
        results = match_patterns("电话+8613812345678", all_patterns)
        assert any(r.text in ("+8613812345678", "13812345678") for r in results)

    def test_mobile_various_prefixes(self, all_patterns):
        """All valid second digits: 3-9."""
        for prefix in ["13", "14", "15", "16", "17", "18", "19"]:
            text = f"{prefix}012345678"
            results = match_patterns(text, all_patterns)
            assert len(results) >= 1, f"Failed to match {text}"

    def test_mobile_too_short(self, all_patterns):
        """10 digits should not match."""
        results = match_patterns("1381234567", all_patterns)
        phone_results = [r for r in results if r.type == "phone"]
        assert len(phone_results) == 0

    def test_mobile_invalid_second_digit(self, all_patterns):
        """Second digit 0, 1, 2 are invalid."""
        for num in ["10012345678", "11012345678", "12012345678"]:
            results = match_patterns(num, all_patterns)
            phone_results = [r for r in results if r.type == "phone"]
            assert len(phone_results) == 0, f"Should not match {num}"

    def test_landline_beijing(self, all_patterns):
        results = match_patterns("座机010-12345678", all_patterns)
        assert any(r.type == "phone" for r in results)

    def test_landline_shanghai(self, all_patterns):
        results = match_patterns("电话021-87654321", all_patterns)
        assert any(r.type == "phone" for r in results)


class TestChineseIdNumber:
    """18-digit Chinese national ID with MOD 11-2 checksum."""

    def test_valid_id(self, all_patterns):
        results = match_patterns("身份证号110101199003074610", all_patterns)
        id_results = [r for r in results if r.type == "id_number"]
        assert len(id_results) == 1

    def test_invalid_checksum(self, all_patterns):
        """Last digit wrong — should not match if validation is on."""
        results = match_patterns("110101199003071235", all_patterns)
        id_results = [r for r in results if r.type == "id_number"]
        assert len(id_results) == 0

    def test_id_with_x_check_digit(self, all_patterns):
        """X is a valid check digit (represents 10)."""
        results = match_patterns("身份证11010119900307002X", all_patterns)
        id_results = [r for r in results if r.type == "id_number"]
        assert len(id_results) == 1

    def test_too_short(self, all_patterns):
        results = match_patterns("11010119900307123", all_patterns)
        id_results = [r for r in results if r.type == "id_number"]
        assert len(id_results) == 0


class TestBankCard:
    """16-19 digit bank card with Luhn checksum."""

    def test_valid_card(self, all_patterns):
        # 6222021234567890123 — need a Luhn-valid number
        # Use known valid: 6222020200001234560 — let me compute one
        # Simple Luhn-valid: 4111111111111111
        results = match_patterns("银行卡4111111111111111", all_patterns)
        card_results = [r for r in results if r.type == "bank_card"]
        assert len(card_results) == 1

    def test_invalid_luhn(self, all_patterns):
        results = match_patterns("4111111111111112", all_patterns)
        card_results = [r for r in results if r.type == "bank_card"]
        assert len(card_results) == 0

    def test_china_unionpay(self, all_patterns):
        """UnionPay cards start with 62."""
        results = match_patterns("卡号6212262200000000004", all_patterns)
        card_results = [r for r in results if r.type == "bank_card"]
        assert len(card_results) == 1


class TestEmail:
    """Email detection (shared across languages)."""

    def test_standard_email(self, all_patterns):
        results = match_patterns("邮箱zhang@example.com", all_patterns)
        email_results = [r for r in results if r.type == "email"]
        assert len(email_results) == 1
        assert email_results[0].text == "zhang@example.com"

    def test_email_with_dots(self, all_patterns):
        results = match_patterns("john.doe@company.co.uk", all_patterns)
        email_results = [r for r in results if r.type == "email"]
        assert len(email_results) == 1

    def test_not_an_email(self, all_patterns):
        results = match_patterns("这不是邮箱@", all_patterns)
        email_results = [r for r in results if r.type == "email"]
        assert len(email_results) == 0


class TestMultiplePII:
    """Text containing multiple PII types."""

    def test_phone_and_id(self, all_patterns):
        text = "手机13812345678，身份证110101199003074610"
        results = match_patterns(text, all_patterns)
        types = {r.type for r in results}
        assert "phone" in types
        assert "id_number" in types

    def test_no_pii(self, all_patterns):
        results = match_patterns("今天天气不错", all_patterns)
        assert len(results) == 0

    def test_empty_text(self, all_patterns):
        results = match_patterns("", all_patterns)
        assert len(results) == 0
