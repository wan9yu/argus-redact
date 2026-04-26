"""Reserved-range fakers for zh PII types.

Each function takes (original_value: str, rng: random.Random) -> str.
The original value is unused for most categorical types (kept for signature
uniformity and so per-value deterministic seeding can happen in the caller).
"""

from __future__ import annotations

import random
import string

# ── Canonical fake-data pools ──

# Note: 张三/李四/王五/赵六/钱七 are extremely common as actual Chinese names,
# but they function as the established cultural placeholder convention (analogous
# to "John Doe" in English) — recognizable as fake by Chinese readers despite
# being valid as real names. The 红楼梦/西游记 minor-character names below have
# very low real-name collision rate by virtue of obscurity.
RESERVED_PERSON_NAMES = (
    "张三",
    "李四",
    "王五",
    "赵六",
    "钱七",
    # 红楼梦小角色 (low real-name collision rate)
    "焦大",
    "茗烟",
    "傻大姐",
    "彩云",
    "佩凤",
    "偕鸳",
    # 西游记小角色
    "卷帘",
    "毕马温",
)

RESERVED_CITIES = (
    ("滨海市", "东江区", ("八荒街", "九垣街", "十方路", "万象路")),
    ("滨海市", "西陆区", ("青鸾街", "白虎街", "玄武路")),
    ("滨海市", "北原区", ("朱雀路", "麒麟街")),
)

PASSPORT_PREFIXES = ("E", "G")

PLATE_SPECIAL_PREFIXES = ("测", "领")

GB11643_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
GB11643_CHECK_CHARS = "10X98765432"


# ── Faker functions ──


def fake_phone_reserved(value: str, rng: random.Random) -> str:
    """Generate a 199-99-XXXXXX mobile number (11 digits).

    Format: 19999 + 6 random digits. 199-99 子段当前未分配运营商。
    """
    suffix = "".join(str(rng.randint(0, 9)) for _ in range(6))
    return "19999" + suffix


def fake_phone_landline_reserved(value: str, rng: random.Random) -> str:
    """Generate a 099-XXXXXXXX landline (区号 099 不存在)."""
    body = "".join(str(rng.randint(0, 9)) for _ in range(8))
    return "099-" + body


def fake_id_number_reserved(value: str, rng: random.Random) -> str:
    """Generate a 999XXX-prefixed 18-char ID with valid GB 11643 checksum.

    Address code 999XXX is not assigned in GB/T 2260 (国家行政区划代码).
    """
    area = "999" + "".join(str(rng.randint(0, 9)) for _ in range(3))
    year = rng.randint(1960, 2005)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    seq = rng.randint(0, 999)
    body = f"{area}{year}{month:02d}{day:02d}{seq:03d}"
    total = sum(int(body[i]) * GB11643_WEIGHTS[i] for i in range(17))
    return body + GB11643_CHECK_CHARS[total % 11]


def fake_bank_card_reserved(value: str, rng: random.Random) -> str:
    """Generate a 999999-BIN bank card with valid Luhn checksum.

    BIN 999999 is not assigned in 银联 BIN allocation.
    """
    body = "999999" + "".join(str(rng.randint(0, 9)) for _ in range(9))
    digits = [int(d) for d in body]
    doubled = digits[-1::-2]
    not_doubled = digits[-2::-2]
    doubled_sum = sum(d * 2 - 9 if d * 2 > 9 else d * 2 for d in doubled)
    total = doubled_sum + sum(not_doubled)
    check = (10 - total % 10) % 10
    return body + str(check)


def fake_passport_reserved(value: str, rng: random.Random) -> str:
    """Generate E99999XXX or G99999XXX passport number (实际前缀 + 假序列)."""
    prefix = rng.choice(PASSPORT_PREFIXES)
    serial = "".join(str(rng.randint(0, 9)) for _ in range(3))
    return f"{prefix}99999{serial}"


def fake_license_plate_reserved(value: str, rng: random.Random) -> str:
    """Generate '测/领'-prefixed plate with 99999 body."""
    prefix = rng.choice(PLATE_SPECIAL_PREFIXES)
    letter = rng.choice(string.ascii_uppercase)
    return f"{prefix}{letter}99999"


def fake_address_reserved(value: str, rng: random.Random) -> str:
    """Generate a 滨海市 fictional address (city does not exist in real China)."""
    city, district, streets = rng.choice(RESERVED_CITIES)
    street = rng.choice(streets)
    num = rng.randint(1, 999)
    return f"{city}{district}{street}{num}号"


def fake_person_reserved(value: str, rng: random.Random) -> str:
    """Pick a name from the canonical fake-name table."""
    return rng.choice(RESERVED_PERSON_NAMES)
