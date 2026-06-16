"""Chinese regex patterns for Layer 1 PII detection.

Person name detection is handled separately by person.py (candidate + scoring).
This module only contains structural PII patterns (phone, ID, bank card, etc.).
"""

import re

from argus_redact.lang.shared.patterns import validate_luhn as _validate_luhn

# Leading verbs/particles/questions stripped from org/school candidates before validation.
# Matched via one-pass longest-prefix scan, so order within the tuple is irrelevant.
_LEADING_NOISE = (
    "请查一下",
    "请查下",
    "请查",
    "查一下",
    "查下",
    "就职于",
    "供职于",
    "任职于",
    "毕业于",
    "就读于",
    "就读",
    "考入",
    "考上",
    "去过",
    "到过",
    "这是",
    "那是",
    "这个",
    "那个",
    "那里",
    "这里",
    "在",
    "去",
    "从",
    "到",
    "被",
    "给",
    "让",
    "有",
    "是",
    "的",
    "了",
    "和",
    "与",
    "把",
    "将",
    "已",
    "问",
    "看",
    "找",
    "一下",
)
_ORG_SUFFIXES = (
    "股份有限公司",
    "有限责任公司",
    "有限公司",
    "责任公司",
    "集团公司",
    "集团",
    "公司",
    "企业",
    "工厂",
    "银行",
    "保险",
    "证券",
    "基金",
    "医院",
    "诊所",
    "药房",
    "事务所",
    "研究院",
    "研究所",
    "实验室",
)
_SCHOOL_SUFFIXES = (
    "大学",
    "学院",
    "中学",
    "小学",
    "高中",
    "初中",
    "附中",
    "附小",
    "实验学校",
    "外国语学校",
    "师范学校",
    "职业学校",
    "技术学校",
    "幼儿园",
    "书院",
    "学堂",
    "党校",
)


def _has_name_before_suffix(value: str, suffixes: tuple[str, ...]) -> bool:
    """After stripping leading verb/particle noise, verify a name char remains before suffix."""
    stripped = value
    while True:
        for noise in _LEADING_NOISE:
            if stripped.startswith(noise) and len(stripped) > len(noise):
                stripped = stripped[len(noise) :]
                break
        else:
            break
    return any(stripped.endswith(suffix) and len(stripped) > len(suffix) for suffix in suffixes)


def _validate_organization(value: str) -> bool:
    return _has_name_before_suffix(value, _ORG_SUFFIXES)


def _validate_school(value: str) -> bool:
    return _has_name_before_suffix(value, _SCHOOL_SUFFIXES)


def _validate_id_number(value: str) -> bool:
    """MOD 11-2 checksum for 18-digit Chinese national ID.

    Strict: rejects invalid checksums to avoid false positives on 18-digit
    order numbers, serial numbers, etc. Trade-off: a user who types one wrong
    digit in their ID number will not have it detected.
    """
    value = value.replace(" ", "").replace("-", "").upper()
    if len(value) != 18:
        return False
    if not value[:17].isdigit():
        return False
    if value[17] not in "0123456789X":
        return False
    if value[0] == "0":
        return False
    return gb11643_check_char(value[:17]) == value[17]


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


def _validate_hkid(value: str) -> bool:
    """Validate HKID format L(L)NNNNNN(C). Strips parens to extract check."""
    m = _HKID_BODY_RE.fullmatch(value)
    if not m:
        return False
    letters, digits, check = m.group(1), m.group(2), m.group(3)
    return hkid_check_digit(letters, digits) == check


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


def _validate_twid(value: str) -> bool:
    """Validate Republic of China (Taiwan) national ID card number."""
    if len(value) != 10 or not value[0].isalpha() or not value[1:].isdigit():
        return False
    if value[0] not in _TWID_LETTER_TO_CODE:
        return False
    return twid_check_digit(value[0], value[1:9]) == value[9]


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


def _validate_credit_code(value: str) -> bool:
    """MOD 31 checksum for 18-char Unified Social Credit Code (GB 32100-2015)."""
    value = value.upper()
    if len(value) != 18:
        return False
    if any(c not in _CREDIT_CODE_CHAR_TO_VAL for c in value):
        return False
    total = sum(_CREDIT_CODE_CHAR_TO_VAL[value[i]] * _CREDIT_CODE_WEIGHTS[i] for i in range(17))
    check = (31 - total % 31) % 31
    return _CREDIT_CODE_CHAR_TO_VAL[value[17]] == check


def _validate_bank_card(value: str) -> bool:
    """Validate bank card: Luhn OR known BIN prefix."""
    digits = "".join(d for d in value if d.isdigit())
    if len(digits) < 16:
        return False
    # Pass if Luhn valid
    if _validate_luhn(value):
        return True
    # Fallback: accept if starts with a known Chinese bank BIN
    return digits[:6] in _BANK_BINS


# Pattern DATA is the SSOT in the Rust core (RON); read it here. The deferred
# `organization`/`school` validators (above) are re-attached by core_patterns
# as `validate` callables.
from argus_redact.lang._loader import core_patterns

PATTERNS = core_patterns("zh")
