"""Chinese regex patterns for Layer 1 PII detection.

Person name detection is handled separately by person.py (candidate + scoring).
This module only contains structural PII patterns (phone, ID, bank card, etc.).
"""

import re


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


_HKID_BODY_RE = re.compile(r"([A-Z]{1,2})(\d{6})\((\d|X)\)")


_TWID_LETTER_TO_CODE = {
    "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16,
    "H": 17, "I": 34, "J": 18, "K": 19, "L": 20, "M": 21, "N": 22,
    "O": 35, "P": 23, "Q": 24, "R": 25, "S": 26, "T": 27, "U": 28,
    "V": 29, "W": 32, "X": 30, "Y": 31, "Z": 33,
}


def twid_check_digit(letter: str, digits: str) -> str:
    """Compute TWID check per ROC weighted-sum mod-10 algorithm.

    `digits` is the 8-digit body; returns 1-char check digit.
    Letter maps to a 2-digit region code (A=10..Z=33); first digit is
    multiplied by 1, second by 9, then body digits use weights [8..1].
    """
    code = _TWID_LETTER_TO_CODE[letter]
    n1, n2 = code // 10, code % 10
    weights_body = [8, 7, 6, 5, 4, 3, 2, 1]
    total = n1 * 1 + n2 * 9
    for d, w in zip(digits, weights_body):
        total += int(d) * w
    rem = total % 10
    return str((10 - rem) % 10)


# Known Chinese bank BIN prefixes (6 digits)
_BANK_BINS = {
    "621700",
    "621660",
    "621662",
    "621663",  # 建设银行
    "622202",
    "622200",
    "622208",
    "621225",  # 工商银行
    "622848",
    "622849",
    "620059",
    "621282",  # 农业银行
    "622568",
    "622569",
    "625912",
    "625911",  # 中国银行
    "622588",
    "622598",
    "621483",
    "622575",  # 招商银行
    "622155",
    "622156",
    "622157",
    "621002",  # 交通银行
    "622689",
    "622688",
    "621691",
    "622622",  # 民生银行
    "622668",
    "622669",
    "622670",
    "622671",  # 中信银行
    "622630",
    "622631",
    "622632",
    "622633",  # 浦发银行
    "621283",
    "621285",
    "621286",
    "621484",  # 光大银行
    "622580",
    "622581",
    "622582",
    "622583",  # 兴业银行
    "622150",
    "622151",
    "622152",
    "622153",  # 平安银行
    "622700",
    "622701",
    "622690",
    "622692",  # 邮储银行
}


# GB 32100-2015 Unified Social Credit Code constants
_CREDIT_CODE_CHARSET = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_CREDIT_CODE_CHAR_TO_VAL = {c: i for i, c in enumerate(_CREDIT_CODE_CHARSET)}
_CREDIT_CODE_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)


# Pattern DATA is the SSOT in the Rust core (RON); read it here. Validation for
# each type (organization, school, etc.) also runs in the Rust core
# (validators.rs) — there is no Python validate callback.
from argus_redact.lang._loader import core_patterns

PATTERNS = core_patterns("zh")
