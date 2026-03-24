"""Tests for Chinese regex patterns."""

import pytest

from argus_redact.pure.patterns import match_patterns
from tests.conftest import (
    PHONE_MOBILE, PHONE_MOBILE_WITH_CC, PHONE_LANDLINE_BJ, PHONE_LANDLINE_SH,
    ID_VALID, ID_VALID_X, ID_INVALID_CHECKSUM,
    BANK_CARD_VISA, BANK_CARD_UNIONPAY, BANK_CARD_INVALID,
    EMAIL_SIMPLE, EMAIL_DOTS,
)


class TestChinesePhone:
    """Chinese mobile and landline phone numbers."""

    def test_mobile_standard(self, zh_patterns):
        results = match_patterns(f"手机号{PHONE_MOBILE}", zh_patterns)
        assert len(results) == 1
        assert results[0].text == PHONE_MOBILE
        assert results[0].type == "phone"

    def test_mobile_with_country_code(self, zh_patterns):
        results = match_patterns(f"电话{PHONE_MOBILE_WITH_CC}", zh_patterns)
        assert any(r.text in (PHONE_MOBILE_WITH_CC, PHONE_MOBILE) for r in results)

    @pytest.mark.parametrize("prefix", ["13", "14", "15", "16", "17", "18", "19"])
    def test_mobile_various_prefixes(self, zh_patterns, prefix):
        text = f"{prefix}012345678"
        results = match_patterns(text, zh_patterns)
        assert len(results) >= 1, f"Failed to match {text}"

    def test_mobile_too_short(self, zh_patterns):
        results = match_patterns("1381234567", zh_patterns)
        phone_results = [r for r in results if r.type == "phone"]
        assert len(phone_results) == 0

    @pytest.mark.parametrize("num", ["10012345678", "11012345678", "12012345678"])
    def test_mobile_invalid_second_digit(self, zh_patterns, num):
        results = match_patterns(num, zh_patterns)
        phone_results = [r for r in results if r.type == "phone"]
        assert len(phone_results) == 0, f"Should not match {num}"

    def test_landline_beijing(self, zh_patterns):
        results = match_patterns(f"座机{PHONE_LANDLINE_BJ}", zh_patterns)
        assert any(r.type == "phone" for r in results)

    def test_landline_shanghai(self, zh_patterns):
        results = match_patterns(f"电话{PHONE_LANDLINE_SH}", zh_patterns)
        assert any(r.type == "phone" for r in results)


class TestChineseIdNumber:
    """18-digit Chinese national ID with MOD 11-2 checksum."""

    def test_valid_id(self, zh_patterns):
        results = match_patterns(f"身份证号{ID_VALID}", zh_patterns)
        id_results = [r for r in results if r.type == "id_number"]
        assert len(id_results) == 1

    def test_invalid_checksum(self, zh_patterns):
        results = match_patterns(ID_INVALID_CHECKSUM, zh_patterns)
        id_results = [r for r in results if r.type == "id_number"]
        assert len(id_results) == 0

    def test_id_with_x_check_digit(self, zh_patterns):
        results = match_patterns(f"身份证{ID_VALID_X}", zh_patterns)
        id_results = [r for r in results if r.type == "id_number"]
        assert len(id_results) == 1

    def test_too_short(self, zh_patterns):
        results = match_patterns("11010119900307123", zh_patterns)
        id_results = [r for r in results if r.type == "id_number"]
        assert len(id_results) == 0


class TestBankCard:
    """16-19 digit bank card with Luhn checksum."""

    def test_valid_card(self, zh_patterns):
        results = match_patterns(f"银行卡{BANK_CARD_VISA}", zh_patterns)
        card_results = [r for r in results if r.type == "bank_card"]
        assert len(card_results) == 1

    def test_invalid_luhn(self, zh_patterns):
        results = match_patterns(BANK_CARD_INVALID, zh_patterns)
        card_results = [r for r in results if r.type == "bank_card"]
        assert len(card_results) == 0

    def test_china_unionpay(self, zh_patterns):
        results = match_patterns(f"卡号{BANK_CARD_UNIONPAY}", zh_patterns)
        card_results = [r for r in results if r.type == "bank_card"]
        assert len(card_results) == 1


class TestEmail:
    """Email detection (shared across languages)."""

    def test_standard_email(self, zh_patterns):
        results = match_patterns(f"邮箱{EMAIL_SIMPLE}", zh_patterns)
        email_results = [r for r in results if r.type == "email"]
        assert len(email_results) == 1
        assert email_results[0].text == EMAIL_SIMPLE

    def test_email_with_dots(self, zh_patterns):
        results = match_patterns(EMAIL_DOTS, zh_patterns)
        email_results = [r for r in results if r.type == "email"]
        assert len(email_results) == 1

    def test_not_an_email(self, zh_patterns):
        results = match_patterns("这不是邮箱@", zh_patterns)
        email_results = [r for r in results if r.type == "email"]
        assert len(email_results) == 0


class TestMultiplePII:
    """Text containing multiple PII types."""

    def test_phone_and_id(self, zh_patterns):
        text = f"手机{PHONE_MOBILE}，身份证{ID_VALID}"
        results = match_patterns(text, zh_patterns)
        types = {r.type for r in results}
        assert "phone" in types
        assert "id_number" in types

    def test_no_pii(self, zh_patterns):
        results = match_patterns("今天天气不错", zh_patterns)
        assert len(results) == 0

    def test_empty_text(self, zh_patterns):
        results = match_patterns("", zh_patterns)
        assert len(results) == 0
