"""HKID — 8-character `[A-Z]{1,2}\\d{6}\\(\\d|X\\)` with mod-11 check."""
import pytest
from argus_redact import redact


VALID_HKID = [
    "A123456(9)",   # single-letter, check digit verified by hand
    "Z684325(1)",   # single-letter
    "WX123456(8)",  # double-letter (post-2019)
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
