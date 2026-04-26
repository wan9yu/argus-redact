"""Chinese PII faker functions — generate realistic fake values.

Each function takes a random.Random instance and returns a string.
These are attached to PIITypeDef.faker for spec-driven data generation.

This module is the SINGLE SOURCE of Chinese fake data pools.
Generators (tests/benchmark/generators/zh.py) should import from here.
"""

from __future__ import annotations

import random
import string

# ── Data pools (canonical source — do not duplicate elsewhere) ──

SURNAMES = [
    "王",
    "李",
    "张",
    "刘",
    "陈",
    "杨",
    "赵",
    "黄",
    "周",
    "吴",
    "徐",
    "孙",
    "胡",
    "朱",
    "高",
    "林",
    "何",
    "郭",
    "马",
    "罗",
    "梁",
    "宋",
    "郑",
    "谢",
    "韩",
    "唐",
    "冯",
    "于",
    "董",
    "萧",
    "程",
    "曹",
    "袁",
    "邓",
    "许",
    "傅",
    "沈",
    "曾",
    "彭",
    "吕",
    "苏",
    "卢",
    "蒋",
    "蔡",
    "贾",
    "丁",
    "魏",
    "薛",
    "叶",
    "阎",
]

GIVEN_NAMES = [
    "伟",
    "芳",
    "娜",
    "秀英",
    "敏",
    "静",
    "丽",
    "强",
    "磊",
    "洋",
    "勇",
    "艳",
    "杰",
    "娟",
    "涛",
    "明",
    "超",
    "秀兰",
    "霞",
    "平",
    "刚",
    "桂英",
    "文",
    "华",
    "建华",
    "玉兰",
    "建国",
    "建军",
    "志强",
    "秀珍",
    "晓明",
    "子轩",
    "浩然",
    "宇轩",
    "梓涵",
    "雨桐",
    "欣怡",
    "子墨",
    "博文",
    "思远",
    "嘉琪",
    "诗涵",
    "梦瑶",
    "俊杰",
    "天佑",
    "雅琴",
    "婷婷",
    "小红",
    "大伟",
    "志远",
]

ID_AREA_CODES = [
    "110101",
    "110102",
    "110105",
    "110108",  # 北京
    "310101",
    "310104",
    "310105",
    "310107",  # 上海
    "440103",
    "440105",
    "440106",
    "440304",  # 广东
    "330102",
    "330106",
    "330108",
    "330109",  # 浙江
    "320102",
    "320104",
    "320105",
    "320106",  # 江苏
    "510104",
    "510105",
    "510107",
    "510108",  # 四川
    "420102",
    "420103",
    "420104",
    "420106",  # 湖北
]

BANK_BINS = [
    "621700",  # 建设银行
    "622202",  # 工商银行
    "622848",  # 农业银行
    "622568",  # 中国银行
    "622588",  # 招商银行
    "622155",  # 交通银行
    "622689",  # 民生银行
    "622668",  # 中信银行
    "621483",  # 光大银行
    "622630",  # 浦发银行
]

PLATE_PREFIXES = [
    "京",
    "沪",
    "粤",
    "浙",
    "苏",
    "鲁",
    "川",
    "豫",
    "鄂",
    "湘",
    "闽",
    "皖",
    "赣",
    "辽",
    "吉",
    "黑",
    "陕",
    "渝",
    "津",
    "冀",
]

EMAIL_DOMAINS = [
    "qq.com",
    "163.com",
    "126.com",
    "sina.com",
    "gmail.com",
    "outlook.com",
    "foxmail.com",
    "yeah.net",
    "sohu.com",
    "aliyun.com",
]

PINYIN_PARTS = [
    "wang",
    "li",
    "zhang",
    "liu",
    "chen",
    "yang",
    "zhao",
    "huang",
    "zhou",
    "wu",
    "xu",
    "sun",
    "hu",
    "zhu",
    "gao",
    "lin",
    "he",
    "guo",
    "wei",
    "fang",
    "na",
    "min",
    "jing",
    "qiang",
    "lei",
    "jie",
    "tao",
    "ming",
    "chao",
    "xia",
    "ping",
    "gang",
    "wen",
    "hua",
    "yong",
]

PROVINCES = [
    ("北京市", "北京市", ["朝阳区", "海淀区", "东城区", "西城区", "丰台区", "通州区"]),
    ("上海市", "上海市", ["浦东新区", "黄浦区", "徐汇区", "静安区", "长宁区", "虹口区"]),
    ("广东省", "广州市", ["天河区", "越秀区", "海珠区", "白云区", "番禺区", "荔湾区"]),
    ("广东省", "深圳市", ["南山区", "福田区", "罗湖区", "宝安区", "龙岗区", "龙华区"]),
    ("浙江省", "杭州市", ["西湖区", "上城区", "拱墅区", "滨江区", "萧山区", "余杭区"]),
    ("江苏省", "南京市", ["玄武区", "鼓楼区", "建邺区", "秦淮区", "栖霞区", "江宁区"]),
    ("四川省", "成都市", ["武侯区", "锦江区", "青羊区", "金牛区", "成华区", "龙泉驿区"]),
    ("湖北省", "武汉市", ["武昌区", "洪山区", "江汉区", "汉阳区", "青山区", "江岸区"]),
    ("山东省", "济南市", ["历下区", "市中区", "天桥区", "槐荫区", "历城区", "长清区"]),
    ("河南省", "郑州市", ["金水区", "中原区", "二七区", "管城区", "惠济区", "上街区"]),
    ("福建省", "福州市", ["鼓楼区", "台江区", "仓山区", "晋安区", "马尾区", "长乐区"]),
    ("湖南省", "长沙市", ["岳麓区", "芙蓉区", "天心区", "开福区", "雨花区", "望城区"]),
]

STREETS = [
    "建国路",
    "中山路",
    "人民路",
    "解放路",
    "长安街",
    "南京路",
    "和平路",
    "文化路",
    "科技路",
    "学院路",
    "花园路",
    "创业路",
    "朝阳路",
    "光明路",
    "幸福路",
    "复兴路",
    "滨河路",
    "迎宾路",
]

PERSON_PREFIXES = ["客户", "用户", "患者", "联系人", "收件人"]


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
    return "护照号" + prefix + digits


def fake_license_plate(rng: random.Random) -> str:
    prefix = rng.choice(PLATE_PREFIXES)
    letter = rng.choice(string.ascii_uppercase)
    chars = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    return prefix + letter + chars


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


def fake_address(rng: random.Random) -> str:
    province, city, districts = rng.choice(PROVINCES)
    district = rng.choice(districts)
    street = rng.choice(STREETS)
    num = rng.randint(1, 999)
    return f"{province}{city}{district}{street}{num}号"


def fake_credit_code(rng: random.Random) -> str:
    """Generate a valid Unified Social Credit Code (GB 32100-2015)."""
    from argus_redact.lang.zh.patterns import (
        _CREDIT_CODE_CHAR_TO_VAL,
        _CREDIT_CODE_CHARSET,
        _CREDIT_CODE_WEIGHTS,
    )

    prefix = rng.choice(["91", "92", "52", "51", "11", "12"])
    area = rng.choice(ID_AREA_CODES)
    body = "".join(rng.choice(_CREDIT_CODE_CHARSET) for _ in range(9))
    code17 = prefix + area + body
    total = sum(_CREDIT_CODE_CHAR_TO_VAL[code17[i]] * _CREDIT_CODE_WEIGHTS[i] for i in range(17))
    check = (31 - total % 31) % 31
    return code17 + _CREDIT_CODE_CHARSET[check]


def fake_qq(rng: random.Random) -> str:
    length = rng.randint(5, 11)
    first = str(rng.randint(1, 9))
    rest = "".join(str(rng.randint(0, 9)) for _ in range(length - 1))
    return "QQ" + first + rest


def fake_wechat(rng: random.Random) -> str:
    first = rng.choice(string.ascii_lowercase)
    length = rng.randint(5, 15)
    rest = "".join(rng.choice(string.ascii_lowercase + string.digits + "_") for _ in range(length))
    return "微信号" + first + rest


def fake_date_of_birth(rng: random.Random) -> str:
    year = rng.randint(1950, 2005)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    keyword = rng.choice(["出生日期", "生日", "出生", "生于"])
    fmt = rng.choice(["nian", "dash", "slash"])
    if fmt == "nian":
        return f"{keyword}{year}年{month}月{day}日"
    elif fmt == "dash":
        return f"{keyword}{year}-{month:02d}-{day:02d}"
    else:
        return f"{keyword}{year}/{month:02d}/{day:02d}"


def fake_military_id(rng: random.Random) -> str:
    keyword = rng.choice(["军字第", "武字第"])
    digits = "".join(str(rng.randint(0, 9)) for _ in range(8))
    return f"{keyword}{digits}号"


def fake_social_security(rng: random.Random) -> str:
    keyword = rng.choice(["社保号", "社保卡号", "社会保障号"])
    id_num = fake_id_number(rng)
    return f"{keyword}{id_num}"


def fake_email(rng: random.Random) -> str:
    local = rng.choice(PINYIN_PARTS) + rng.choice(PINYIN_PARTS) + str(rng.randint(1, 999))
    domain = rng.choice(EMAIL_DOMAINS)
    return f"{local}@{domain}"
