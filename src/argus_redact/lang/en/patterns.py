"""English regex patterns for Layer 1 PII detection."""

from argus_redact.lang.zh.patterns import _validate_luhn


def _validate_ssn(value: str) -> bool:
    """Basic SSN validation: area != 000, group != 00, serial != 0000."""
    parts = value.split("-")
    if len(parts) != 3:
        return False
    area, group, serial = parts
    if area == "000" or group == "00" or serial == "0000":
        return False
    return True


def _validate_credit_card_luhn(value: str) -> bool:
    """Luhn checksum for credit card with optional separators."""
    digits_only = value.replace("-", "").replace(" ", "")
    if not digits_only.isdigit():
        return False
    return _validate_luhn(digits_only)


PATTERNS = [
    {
        "type": "ssn",
        "label": "[SSN REDACTED]",
        "pattern": r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
        "validate": _validate_ssn,
        "check_context": True,
        "description": "US Social Security Number",
    },
    {
        "type": "phone",
        "label": "[PHONE REDACTED]",
        "pattern": (r"(?:\+1[-.\s]?)?" r"\(?\d{3}\)?[-.\s]?" r"\d{3}[-.\s]?" r"\d{4}" r"(?!\d)"),
        "description": "North American phone number",
    },
    {
        "type": "credit_card",
        "label": "[CARD REDACTED]",
        "pattern": (r"(?<!\d)" r"[3-6]\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}" r"(?!\d)"),
        "validate": _validate_credit_card_luhn,
        "check_context": True,
        "description": "Credit card number (Luhn checksum)",
    },
]
