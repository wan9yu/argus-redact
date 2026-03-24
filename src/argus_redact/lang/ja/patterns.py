"""Japanese regex patterns for Layer 1 PII detection."""


def _validate_jp_phone_length(value: str) -> bool:
    """Japanese phone numbers should have 10-11 digits total."""
    digits = value.replace("-", "")
    return 10 <= len(digits) <= 11


def _validate_my_number(value: str) -> bool:
    """Check digit validation for Japanese My Number (個人番号)."""
    digits = value.replace(" ", "")
    if len(digits) != 12:
        return False
    if not digits.isdigit():
        return False
    weights = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
    total = sum(int(d) * w for d, w in zip(digits[:11], weights))
    remainder = total % 11
    check = 0 if remainder <= 1 else 11 - remainder
    return int(digits[11]) == check


PATTERNS = [
    {
        "type": "phone",
        "label": "[電話番号]",
        "pattern": r"0[789]0-?\d{4}-?\d{4}(?!\d)",
        "description": "Japanese mobile phone (070/080/090)",
    },
    {
        "type": "phone",
        "label": "[電話番号]",
        "pattern": r"0[1-9]\d{0,3}-?\d{1,4}-?\d{4}(?!\d)",
        "validate": _validate_jp_phone_length,
        "description": "Japanese landline phone",
    },
    {
        "type": "my_number",
        "label": "[マイナンバー]",
        "pattern": r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)",
        "validate": _validate_my_number,
        "description": "Japanese My Number (12 digits, check digit)",
    },
]
