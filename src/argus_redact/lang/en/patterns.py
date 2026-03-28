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


_MONTHS = (
    r"(?:January|February|March|April|May|June"
    r"|July|August|September|October|November|December"
    r"|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
)

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
    {
        "type": "address",
        "label": "[ADDRESS REDACTED]",
        "pattern": (
            r"\d{1,5}\s+"
            r"(?:[A-Z][a-z]+\s+){1,3}"
            r"(?:St(?:reet)?|Ave(?:nue)?|Rd|Road|Blvd|Boulevard|"
            r"Dr(?:ive)?|Ln|Lane|Way|Ct|Court|Pl(?:ace)?|Cir(?:cle)?)"
            r"(?:\s*,\s*(?:Apt|Suite|Unit|#)\s*\w+)?"
        ),
        "description": "US street address (number + street name + type)",
    },
    {
        "type": "date_of_birth",
        "label": "[DOB REDACTED]",
        "pattern": (
            r"(?:date\s+of\s+birth|DOB|birthdate|birthday|born(?:\s+on)?)"
            r"\s*[:.]?\s*"
            r"(?P<date_of_birth>"
            # M/D/YYYY or MM/DD/YYYY
            r"(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:19|20)\d{2}"
            r"|"
            # YYYY-MM-DD
            r"(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
            r"|"
            # Month D, YYYY or Month D YYYY
            rf"{_MONTHS}\s+\d{{1,2}},?\s+(?:19|20)\d{{2}}"
            r"|"
            # D(st/nd/rd/th) Month YYYY
            r"\d{1,2}(?:st|nd|rd|th)?\s+"
            rf"{_MONTHS}\s+(?:19|20)\d{{2}}"
            r")"
        ),
        "group": "date_of_birth",
        "description": "English date of birth (keyword-triggered, multiple formats)",
    },
    {
        "type": "us_passport",
        "label": "[PASSPORT REDACTED]",
        "pattern": (
            r"(?i:passport\s*(?:number|no\.?|#)?)\s*[:.]?\s*"
            r"(?P<us_passport>[A-Za-z]\d{8})"
            r"(?!\d)"
        ),
        "group": "us_passport",
        "description": "US passport number (keyword-triggered, letter + 8 digits)",
    },
]
