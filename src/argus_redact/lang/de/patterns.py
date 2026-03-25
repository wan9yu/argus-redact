"""German regex patterns for Layer 1 PII detection."""


def _validate_tax_id(value: str) -> bool:
    """German tax ID (Steuerliche Identifikationsnummer): 11 digits, no 0 start."""
    digits = value.replace(" ", "")
    if len(digits) != 11 or digits[0] == "0":
        return False
    return digits.isdigit()


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
        "pattern": r"(?:\+49|0049|0)[-\s]?\d{2,5}[-/\s]?\d{3,10}(?!\d)",
        "description": "German phone number",
    },
    {
        "type": "iban",
        "label": "[IBAN]",
        "pattern": r"DE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}",
        "description": "German IBAN",
    },
]
