"""Shared test fixtures for argus-redact."""

import pytest

from argus_redact._types import PatternMatch
from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS


# ── Test data: well-known PII values ──
# All values are synthetic. ID and card numbers have valid checksums.

PHONE_MOBILE = "13812345678"
PHONE_MOBILE_WITH_CC = "+8613812345678"
PHONE_LANDLINE_BJ = "010-12345678"
PHONE_LANDLINE_SH = "021-87654321"

ID_VALID = "110101199003074610"           # MOD 11-2 checksum OK
ID_VALID_X = "11010119900307002X"         # check digit is X
ID_INVALID_CHECKSUM = "110101199003071235"  # last digit wrong

BANK_CARD_VISA = "4111111111111111"       # Luhn OK
BANK_CARD_UNIONPAY = "6212262200000000004"  # Luhn OK
BANK_CARD_INVALID = "4111111111111112"    # Luhn fail

EMAIL_SIMPLE = "zhang@example.com"
EMAIL_DOTS = "john.doe@company.co.uk"
EMAIL_PLUS = "user+tag@example.com"


@pytest.fixture
def sample_key():
    """A typical key mapping pseudonyms to originals."""
    return {
        "P-037": "王五",
        "P-012": "张三",
        "[咖啡店]": "星巴克",
        "[某公司]": "阿里",
        "[手机号已脱敏]": PHONE_MOBILE,
    }


@pytest.fixture
def zh_patterns():
    """Chinese regex patterns + shared patterns."""
    return ZH_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def shared_patterns():
    """Shared (cross-language) patterns only."""
    return list(SHARED_PATTERNS)


def make_match(text, entity_type, start, end=None):
    """Helper to create a PatternMatch with less boilerplate."""
    if end is None:
        end = start + len(text)
    return PatternMatch(text=text, type=entity_type, start=start, end=end)
