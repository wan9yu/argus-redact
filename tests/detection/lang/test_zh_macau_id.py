"""Macau ID — `[1-9]/\\d{6}/\\d` (format-only validation)."""
import pytest
from argus_redact import redact


VALID_MACAU = [
    "1/234567/8",
    "5/123456/0",
    "7/000001/2",
]
INVALID_MACAU = [
    "0/234567/8",   # leading 0 not assigned
    "1/234567",     # missing check
    "1/2345678/8",  # 7 body digits
]


@pytest.mark.parametrize("text", VALID_MACAU)
def test_macau_detected(text):
    out, key = redact(text, lang="zh", mode="fast", seed=42)
    assert text not in out


@pytest.mark.parametrize("text", INVALID_MACAU)
def test_invalid_macau_not_detected(text):
    out, key = redact(text, lang="zh", mode="fast", seed=42)
    assert text in out
