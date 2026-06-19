"""Chinese regex patterns for Layer 1 PII detection.

Person name detection is handled separately by person.py (candidate + scoring).
This module only contains structural PII patterns (phone, ID, bank card, etc.).
"""


# Kept for fixture generation only (tests/benchmark/generators/fakers_zh_real.py); runtime validation lives in Rust validators.rs.
GB11643_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
GB11643_CHECK_CHARS = "10X98765432"


def gb11643_check_char(body17: str) -> str:
    """Compute GB 11643 check character for a 17-digit ID body."""
    total = sum(int(body17[i]) * GB11643_WEIGHTS[i] for i in range(17))
    return GB11643_CHECK_CHARS[total % 11]


def hkid_check_digit(letters: str, digits: str) -> str:
    """Compute HKID check digit per Wikipedia HKID algorithm.

    `letters` is 1-2 uppercase ASCII letters; `digits` is 6 digits.
    Single-letter HKIDs are padded with a leading space (value 36) so the
    body+letter is always 8 chars before the check digit. Letters map
    A=1..Z=26; weights [9,8,7,6,5,4,3,2] over the 8-char body+letter.
    Returns the check character ('0'-'9' or 'X' for 10).
    """
    pad = " " if len(letters) == 1 else ""
    body = pad + letters + digits
    weights = [9, 8, 7, 6, 5, 4, 3, 2]
    total = 0
    for ch, w in zip(body, weights):
        if ch == " ":
            v = 36
        elif ch.isalpha():
            v = ord(ch) - ord("A") + 1
        else:
            v = int(ch)
        total += v * w
    rem = total % 11
    check = (11 - rem) % 11
    return "X" if check == 10 else str(check)


# GB 32100-2015 Unified Social Credit Code constants
_CREDIT_CODE_CHARSET = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_CREDIT_CODE_CHAR_TO_VAL = {c: i for i, c in enumerate(_CREDIT_CODE_CHARSET)}
_CREDIT_CODE_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)


# Pattern DATA is the SSOT in the Rust core (RON); read it here. Validation for
# each type (organization, school, etc.) also runs in the Rust core
# (validators.rs) — there is no Python validate callback.
from argus_redact.lang._loader import core_patterns

PATTERNS = core_patterns("zh")
