"""TWID — `[A-Z]\\d{9}` with weighted-sum mod-10 check."""
import pytest
from argus_redact import redact


VALID_TWID = [
    "A123456789",   # Taipei City (A=10), check digit verified by hand
    "B142536472",   # Taichung (B=11)
    "F131011128",   # New Taipei (F=15)
]
INVALID_TWID = [
    "A123456780",   # wrong check digit
    "A12345678",    # too short (9 chars)
    "1A12345678",   # leading digit (not a letter)
]


@pytest.mark.parametrize("text", VALID_TWID)
def test_twid_detected(text):
    out, key = redact(text, lang="zh", mode="fast", seed=42)
    assert text not in out


@pytest.mark.parametrize("text", INVALID_TWID)
def test_invalid_twid_not_detected(text):
    out, key = redact(text, lang="zh", mode="fast", seed=42)
    assert text in out
