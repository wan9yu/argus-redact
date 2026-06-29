"""Amex (15) and Diners (14) cards must redact, not leak."""

from argus_redact import redact


def test_amex_redacted():
    out, key = redact("card 378282246310005 thanks", lang="en", mode="fast", salt=42)
    assert "378282246310005" not in out  # full PAN must be gone
    assert "378282" in out and "0005" in out and "*" in out  # credit-card mask: BIN + last4 kept
    assert "378282246310005" in key.values()  # key restores the original card


def test_diners_redacted():
    out, key = redact("card 30569309025904 ok", lang="en", mode="fast", salt=42)
    assert "30569309025904" not in out  # full PAN must be gone
    assert "305693" in out and "5904" in out and "*" in out  # credit-card mask: BIN + last4 kept
    assert "30569309025904" in key.values()  # key restores the original card


def test_16_digit_still_redacted():
    out, key = redact("card 4111111111111111", lang="en", mode="fast", salt=42)
    assert "4111111111111111" not in out  # full PAN must be gone
    assert "411111" in out and "1111" in out and "*" in out  # credit-card mask: BIN + last4 kept
    assert "4111111111111111" in key.values()  # key restores the original card
