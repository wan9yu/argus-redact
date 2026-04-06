"""German regex patterns for Layer 1 PII detection."""


def _validate_tax_id(value: str) -> bool:
    """German tax ID (Steuerliche Identifikationsnummer): 11 digits, no 0 start."""
    digits = value.replace(" ", "")
    if len(digits) != 11 or digits[0] == "0":
        return False
    return digits.isdigit()


def _validate_de_phone(value: str) -> bool:
    """German phone number: 10-15 digits total (including country code)."""
    digits = "".join(d for d in value if d.isdigit())
    return 10 <= len(digits) <= 15


PATTERNS = [
    {
        "type": "tax_id",
        "label": "[Steuer-ID]",
        "pattern": r"(?<!\d)\d{2}\s?\d{3}\s?\d{3}\s?\d{3}(?!\d)",
        "validate": _validate_tax_id,
        "description": "German tax ID (Steuerliche Identifikationsnummer, 11 digits)",
    },
    {
        "type": "phone",
        "label": "[Telefonnummer]",
        "pattern": (
            r"(?:\+49|0049)[-\s]?\d{2,4}[-/\s]?\d{3,4}[-/\s]?\d{3,5}(?!\d)"
            r"|(?<!\d)0[1-9]\d{1,4}[-/\s]?\d{3,4}[-/\s]?\d{3,5}(?!\d)"
        ),
        "validate": _validate_de_phone,
        "description": "German phone number (mobile/landline, 10-15 digits)",
    },
    {
        "type": "iban",
        "label": "[IBAN]",
        "pattern": r"DE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}",
        "description": "German IBAN",
    },
]
