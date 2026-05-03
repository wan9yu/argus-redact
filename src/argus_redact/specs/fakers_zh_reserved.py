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

# v0.5.8: pinyin transliterations the LLM might emit when it rephrases
# zh fakes into Latin script. `restore()` matches both the canonical fake
# and its aliases back to the original. Hyphenated and concatenated forms
# both common in real LLM output.
RESERVED_PERSON_NAMES_ALIASES: dict[str, list[str]] = {
    "张三": ["Zhang San", "Zhang3", "ZhangSan"],
    "李四": ["Li Si", "Li4", "LiSi"],
    "王五": ["Wang Wu", "Wang5", "WangWu"],
    "赵六": ["Zhao Liu", "Zhao6", "ZhaoLiu"],
    "钱七": ["Qian Qi", "Qian7", "QianQi"],
    "焦大": ["Jiao Da", "JiaoDa"],
    "茗烟": ["Ming Yan", "MingYan"],
    "傻大姐": ["Sha Dajie", "Silly Big Sister"],
    "彩云": ["Cai Yun", "CaiYun"],
    "佩凤": ["Pei Feng", "PeiFeng"],
    "偕鸳": ["Xie Yuan", "XieYuan"],
    "卷帘": ["Juan Lian", "JuanLian"],
    "毕马温": ["Bi Mawen", "BiMawen"],
}

RESERVED_CITIES = (
    ("滨海市", "东江区", ("八荒街", "九垣街", "十方路", "万象路")),
    ("滨海市", "西陆区", ("青鸾街", "白虎街", "玄武路")),
    ("滨海市", "北原区", ("朱雀路", "麒麟街")),
)

PASSPORT_PREFIXES = ("E", "G")

PLATE_SPECIAL_PREFIXES = ("测", "领")


# ── Faker functions ──


def fake_phone_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate a 199-99-XXXXXX mobile number (11 digits).

    Format: 19999 + 6 random digits. 199-99 子段当前未分配运营商。
    """
    suffix = "".join(str(rng.randint(0, 9)) for _ in range(6))
    return "19999" + suffix, []


def fake_phone_landline_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate a 099-XXXXXXXX landline (区号 099 不存在)."""
    body = "".join(str(rng.randint(0, 9)) for _ in range(8))
    return "099-" + body, []


def fake_id_number_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate a 999XXX-prefixed 18-char ID with valid GB 11643 checksum.

    Address code 999XXX is not assigned in GB/T 2260 (国家行政区划代码).
    """
    from argus_redact.lang.zh.patterns import gb11643_check_char

    area = "999" + "".join(str(rng.randint(0, 9)) for _ in range(3))
    year = rng.randint(1960, 2005)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    seq = rng.randint(0, 999)
    body = f"{area}{year}{month:02d}{day:02d}{seq:03d}"
    return body + gb11643_check_char(body), []


def fake_bank_card_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate a 999999-BIN bank card with valid Luhn checksum.

    BIN 999999 is not assigned in 银联 BIN allocation.
    """
    from argus_redact.lang.shared.patterns import luhn_check_digit

    body = "999999" + "".join(str(rng.randint(0, 9)) for _ in range(9))
    return body + str(luhn_check_digit(body)), []


def fake_passport_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate E99999XXX or G99999XXX passport number (实际前缀 + 假序列)."""
    prefix = rng.choice(PASSPORT_PREFIXES)
    serial = "".join(str(rng.randint(0, 9)) for _ in range(3))
    return f"{prefix}99999{serial}", []


def fake_license_plate_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate '测/领'-prefixed plate with 99999 body."""
    prefix = rng.choice(PLATE_SPECIAL_PREFIXES)
    letter = rng.choice(string.ascii_uppercase)
    return f"{prefix}{letter}99999", []


def fake_address_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate a 滨海市 fictional address (city does not exist in real China)."""
    city, district, streets = rng.choice(RESERVED_CITIES)
    street = rng.choice(streets)
    num = rng.randint(1, 999)
    # Address transliteration is noisy (street/district names rarely round-trip
    # cleanly); deferred to v0.6+. v0.5.8 returns no aliases here.
    return f"{city}{district}{street}{num}号", []


def fake_person_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Pick a name from the canonical fake-name table; emit pinyin aliases."""
    fake = rng.choice(RESERVED_PERSON_NAMES)
    return fake, list(RESERVED_PERSON_NAMES_ALIASES.get(fake, []))


def fake_hkid_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate HKID using `Z` letter prefix + random 6 digits.

    HK uses `Z` for stateless / refugee IDs, deliberately rare in real
    life so reserved-range usage is safe.
    """
    from argus_redact.lang.zh.patterns import hkid_check_digit

    letter = "Z"
    digits = "".join(str(rng.randint(0, 9)) for _ in range(6))
    return f"{letter}{digits}({hkid_check_digit(letter, digits)})", []


def fake_twid_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate TWID with `W` letter (Lienchiang region 32 — geographically tiny)."""
    from argus_redact.lang.zh.patterns import twid_check_digit

    letter = "W"
    digits = "".join(str(rng.randint(0, 9)) for _ in range(8))
    return f"{letter}{digits}{twid_check_digit(letter, digits)}", []


def fake_macau_id_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Use leading `9` (unassigned in real Macau allocations)."""
    body = "".join(str(rng.randint(0, 9)) for _ in range(6))
    check = str(rng.randint(0, 9))
    return f"9/{body}/{check}", []


def fake_taiwan_arc_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Use `WW` prefix (unassigned region pair)."""
    digits = "".join(str(rng.randint(0, 9)) for _ in range(8))
    return f"WW{digits}", []
