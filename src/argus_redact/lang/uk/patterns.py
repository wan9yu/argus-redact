"""UK regex patterns for Layer 1 PII detection."""

PATTERNS = [
    {
        "type": "postcode",
        "label": "[POSTCODE]",
        "pattern": (r"(?<![A-Za-z])" r"[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}" r"(?![A-Za-z])"),
        "description": "UK postcode (e.g. SW1A 1AA, EC1A 1BB)",
    },
    {
        "type": "nino",
        "label": "[NINO]",
        "pattern": (
            r"(?<![A-Za-z])" r"[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]" r"(?![A-Za-z])"
        ),
        "description": "UK National Insurance Number (NINO)",
    },
    {
        "type": "phone",
        "label": "[PHONE]",
        "pattern": r"(?:\+44|0044|0)[-\s]?\d{2,4}[-\s]?\d{3,4}[-\s]?\d{3,4}(?!\d)",
        "description": "UK phone number",
    },
    {
        "type": "nhs_number",
        "label": "[NHS NUMBER]",
        "pattern": r"(?<!\d)\d{3}\s?\d{3}\s?\d{4}(?!\d)",
        "description": "UK NHS number (10 digits)",
    },
]
