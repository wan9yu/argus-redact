"""Indian regex patterns for Layer 1 PII detection."""


def _validate_aadhaar(value: str) -> bool:
    """Aadhaar: 12 digits, cannot start with 0 or 1."""
    digits = value.replace(" ", "").replace("-", "")
    if len(digits) != 12 or digits[0] in "01":
        return False
    return digits.isdigit()


def _validate_pan(value: str) -> bool:
    """PAN: 5 letters + 4 digits + 1 letter, 4th char indicates holder type."""
    if len(value) != 10:
        return False
    return (
        value[:5].isalpha()
        and value[5:9].isdigit()
        and value[9].isalpha()
        and value[3] in "ABCFGHLJPT"
    )


PATTERNS = [
    {
        "type": "aadhaar",
        "label": "[AADHAAR]",
        "pattern": r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)",
        "validate": _validate_aadhaar,
        "description": "Indian Aadhaar number (12 digits)",
    },
    {
        "type": "pan",
        "label": "[PAN]",
        "pattern": r"(?<![A-Za-z])[A-Z]{5}\d{4}[A-Z](?![A-Za-z])",
        "validate": _validate_pan,
        "description": "Indian PAN card (AAAPL1234C format)",
    },
    {
        "type": "phone",
        "label": "[PHONE]",
        "pattern": r"(?:\+91[-\s]?)?[6-9]\d{4}[-\s]?\d{5}(?!\d)",
        "description": "Indian mobile phone number",
    },
]
