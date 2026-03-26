"""Chinese PII faker functions — generate realistic fake values.

Each function takes a random.Random instance and returns a string.
These are attached to PIITypeDef.faker for spec-driven data generation.
"""

from __future__ import annotations

import random
import string

# ── Data pools ──

SURNAMES = [
    "王", "李", "张", "刘", "陈", "杨", "赵", "黄", "周", "吴",
    "徐", "孙", "胡", "朱", "高", "林", "何", "郭", "马", "罗",
    "梁", "宋", "郑", "谢", "韩", "唐", "冯", "于", "董", "萧",
    "程", "曹", "袁", "邓", "许", "傅", "沈", "曾", "彭", "吕",
    "苏", "卢", "蒋", "蔡", "贾", "丁", "魏", "薛", "叶", "阎",
]

GIVEN_NAMES = [
    "伟", "芳", "娜", "秀英", "敏", "静", "丽", "强", "磊", "洋",
    "勇", "艳", "杰", "娟", "涛", "明", "超", "秀兰", "霞", "平",
    "刚", "桂英", "文", "华", "建华", "玉兰", "建国", "建军", "志强", "秀珍",
    "晓明", "子轩", "浩然", "宇轩", "梓涵", "雨桐", "欣怡", "子墨", "博文", "思远",
]

ID_AREA_CODES = [
    "110101", "110102", "110105", "310101", "310104", "310105",
    "440103", "440105", "440304", "330102", "330106", "320102",
    "320104", "510104", "510105", "420102", "420103",
]

BANK_BINS = [
    "621700", "622202", "622848", "622568", "622588",
    "622155", "622689", "622668", "621483", "622630",
]

PLATE_PREFIXES = [
    "京", "沪", "粤", "浙", "苏", "鲁", "川", "豫", "鄂", "湘",
]

EMAIL_DOMAINS = ["qq.com", "163.com", "126.com", "gmail.com", "foxmail.com"]

PINYIN_PARTS = [
    "wang", "li", "zhang", "liu", "chen", "yang", "zhao", "huang",
    "wei", "fang", "na", "min", "jing", "qiang", "lei", "jie",
]


# ── Faker functions ──

def fake_phone(rng: random.Random) -> str:
    prefix = rng.choice(["13", "14", "15", "16", "17", "18", "19"])
    suffix = "".join(str(rng.randint(0, 9)) for _ in range(9))
    return prefix + suffix


def fake_phone_landline(rng: random.Random) -> str:
    area = rng.choice(["010", "021", "0755", "0571", "028", "025"])
    num = "".join(str(rng.randint(0, 9)) for _ in range(8))
    return area + "-" + num


def fake_id_number(rng: random.Random) -> str:
    area = rng.choice(ID_AREA_CODES)
    year = rng.randint(1960, 2005)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    seq = rng.randint(0, 999)
    body = f"{area}{year}{month:02d}{day:02d}{seq:03d}"

    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_chars = "10X98765432"
    total = sum(int(body[i]) * weights[i] for i in range(17))
    check = check_chars[total % 11]
    return body + check


def fake_bank_card(rng: random.Random) -> str:
    bin_prefix = rng.choice(BANK_BINS)
    body = bin_prefix + "".join(str(rng.randint(0, 9)) for _ in range(9))

    digits = [int(d) for d in body]
    odd_sum = sum(digits[-1::-2])
    even_digits = digits[-2::-2]
    even_sum = sum(d * 2 - 9 if d * 2 > 9 else d * 2 for d in even_digits)
    check = (10 - (odd_sum + even_sum) % 10) % 10
    return body + str(check)


def fake_passport(rng: random.Random) -> str:
    prefix = rng.choice(["E", "G"])
    digits = "".join(str(rng.randint(0, 9)) for _ in range(8))
    return prefix + digits


def fake_license_plate(rng: random.Random) -> str:
    prefix = rng.choice(PLATE_PREFIXES)
    letter = rng.choice(string.ascii_uppercase)
    chars = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    return prefix + letter + chars


PERSON_PREFIXES = ["客户", "用户", "患者", "联系人", "收件人"]


def fake_person(rng: random.Random) -> str:
    """Generate name with context prefix so it matches our patterns."""
    prefix = rng.choice(PERSON_PREFIXES)
    surname = rng.choice(SURNAMES)
    given = rng.choice(GIVEN_NAMES)
    return prefix + surname + given


def fake_person_name_only(rng: random.Random) -> str:
    """Generate bare name (without context) for templates that provide their own."""
    surname = rng.choice(SURNAMES)
    given = rng.choice(GIVEN_NAMES)
    return surname + given


PROVINCES_CITIES = [
    ("北京市", "北京市", ["朝阳区", "海淀区", "东城区", "西城区"]),
    ("上海市", "上海市", ["浦东新区", "黄浦区", "徐汇区", "静安区"]),
    ("广东省", "广州市", ["天河区", "越秀区", "海珠区", "白云区"]),
    ("广东省", "深圳市", ["南山区", "福田区", "罗湖区", "宝安区"]),
    ("浙江省", "杭州市", ["西湖区", "上城区", "拱墅区", "滨江区"]),
    ("江苏省", "南京市", ["玄武区", "鼓楼区", "建邺区", "秦淮区"]),
]

STREETS = ["建国路", "中山路", "人民路", "科技路", "学院路", "花园路"]


def fake_address(rng: random.Random) -> str:
    province, city, districts = rng.choice(PROVINCES_CITIES)
    district = rng.choice(districts)
    street = rng.choice(STREETS)
    num = rng.randint(1, 999)
    return f"{province}{city}{district}{street}{num}号"


def fake_email(rng: random.Random) -> str:
    local = rng.choice(PINYIN_PARTS) + rng.choice(PINYIN_PARTS) + str(rng.randint(1, 999))
    domain = rng.choice(EMAIL_DOMAINS)
    return f"{local}@{domain}"
