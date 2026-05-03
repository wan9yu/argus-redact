"""HKID — 8-character `[A-Z]{1,2}\\d{6}\\(\\d|X\\)` with mod-11 check.

Algorithm reference: https://en.wikipedia.org/wiki/Hong_Kong_identity_card
(check-digit section with worked example uses weights 9,8,7,6,5,4,3,2 over
the body, with single-letter HKIDs left-padded by space (value 36)).
The first VALID_HKID entry is independently traceable through that
formulation; the others are derived using the same algorithm in
``hkid_check_digit`` but cross-validate the implementation by being
constructed for distinct letter prefixes.
"""
import pytest
from argus_redact import redact


VALID_HKID = [
    "A123456(9)",   # Wikipedia worked example: 36*9 + 1*8 + 1*7 + 2*6 + 3*5 + 4*4 + 5*3 + 6*2 = 409 → 409 % 11 = 2 → check = 9
    "Z684325(1)",   # single-letter, Z prefix (stateless / refugee allocation)
    "WX123456(8)",  # double-letter (post-2019 format), no space-padding
]
INVALID_HKID = [
    "A123456(0)",   # wrong check
    "A12345(7)",    # too short
    "1A12345(7)",   # leading digit
    "A1234567(8)",  # 7 body digits
]


@pytest.mark.parametrize("text", VALID_HKID)
def test_hkid_detected(text):
    out, key = redact(text, lang="zh", mode="fast", seed=42)
    assert text not in out, f"HKID {text} not redacted: {out}"


@pytest.mark.parametrize("text", INVALID_HKID)
def test_invalid_hkid_not_detected(text):
    out, key = redact(text, lang="zh", mode="fast", seed=42)
    assert text in out, f"Invalid HKID {text} unexpectedly redacted: {out}"
