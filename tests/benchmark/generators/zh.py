"""Chinese synthetic PII benchmark generator.

Generates realistic Chinese text with labeled PII entities.
Covers all PII types supported by argus-redact lang/zh:
  phone, id_number, bank_card, license_plate, address, passport, email, person

Usage:
    python -m tests.benchmark.generators.zh --count 5000 --output pii_bench_zh.jsonl
    python -m tests.benchmark.generators.zh --count 5000 --output pii_bench_zh.jsonl --seed 42
"""

from __future__ import annotations

import argparse
import json
import random
import string
import sys
from dataclasses import asdict, dataclass

# ── Fake data pools ──

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
    "嘉琪", "诗涵", "梦瑶", "俊杰", "天佑", "雅琴", "婷婷", "小红", "大伟", "志远",
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
    "建国路", "中山路", "人民路", "解放路", "长安街", "南京路",
    "和平路", "文化路", "科技路", "学院路", "花园路", "创业路",
    "朝阳路", "光明路", "幸福路", "复兴路", "滨河路", "迎宾路",
]

PLATE_PREFIXES = [
    "京", "沪", "粤", "浙", "苏", "鲁", "川", "豫", "鄂", "湘",
    "闽", "皖", "赣", "辽", "吉", "黑", "陕", "渝", "津", "冀",
]

EMAIL_DOMAINS = [
    "qq.com", "163.com", "126.com", "sina.com", "gmail.com",
    "outlook.com", "foxmail.com", "yeah.net", "sohu.com", "aliyun.com",
]

# ID number area codes (real prefixes)
ID_AREA_CODES = [
    "110101", "110102", "110105", "110108",  # 北京
    "310101", "310104", "310105", "310107",  # 上海
    "440103", "440105", "440106", "440304",  # 广东
    "330102", "330106", "330108", "330109",  # 浙江
    "320102", "320104", "320105", "320106",  # 江苏
    "510104", "510105", "510107", "510108",  # 四川
    "420102", "420103", "420104", "420106",  # 湖北
]

# Bank card BIN prefixes (common Chinese banks)
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


# ── PII generators ──

def _gen_name(rng: random.Random) -> str:
    surname = rng.choice(SURNAMES)
    given = rng.choice(GIVEN_NAMES)
    return surname + given


def _gen_phone(rng: random.Random) -> str:
    prefix = rng.choice(["13", "14", "15", "16", "17", "18", "19"])
    suffix = "".join(str(rng.randint(0, 9)) for _ in range(9))
    return prefix + suffix


def _gen_id_number(rng: random.Random) -> str:
    """Generate valid 18-digit Chinese ID with MOD 11-2 checksum."""
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


def _gen_bank_card(rng: random.Random) -> str:
    """Generate 16-digit card number with Luhn checksum."""
    bin_prefix = rng.choice(BANK_BINS)
    # Generate 9 random digits (6 BIN + 9 random + 1 check = 16)
    body = bin_prefix + "".join(str(rng.randint(0, 9)) for _ in range(9))

    # Luhn checksum
    digits = [int(d) for d in body]
    odd_sum = sum(digits[-1::-2])
    even_digits = digits[-2::-2]
    even_sum = sum(d * 2 - 9 if d * 2 > 9 else d * 2 for d in even_digits)
    check = (10 - (odd_sum + even_sum) % 10) % 10
    return body + str(check)


def _gen_license_plate(rng: random.Random) -> str:
    prefix = rng.choice(PLATE_PREFIXES)
    letter = rng.choice(string.ascii_uppercase)
    # Normal plate: 5 alphanumeric
    chars = "".join(
        rng.choice(string.ascii_uppercase + string.digits)
        for _ in range(5)
    )
    return prefix + letter + chars


def _gen_address(rng: random.Random) -> str:
    province, city, districts = rng.choice(PROVINCES)
    district = rng.choice(districts)
    street = rng.choice(STREETS)
    number = rng.randint(1, 999)
    building = rng.randint(1, 30)
    room = rng.randint(101, 2505)
    return f"{province}{city}{district}{street}{number}号{building}栋{room}室"


def _gen_passport(rng: random.Random) -> str:
    prefix = rng.choice(["E", "G"])
    digits = "".join(str(rng.randint(0, 9)) for _ in range(8))
    return prefix + digits


def _gen_email(rng: random.Random, name: str) -> str:
    """Generate email with a random local part."""
    # Simple pinyin-like local parts (no external dependency)
    PINYIN_NAMES = [
        "wang", "li", "zhang", "liu", "chen", "yang", "zhao", "huang",
        "zhou", "wu", "xu", "sun", "hu", "zhu", "gao", "lin", "he", "guo",
        "wei", "fang", "na", "min", "jing", "qiang", "lei", "jie", "tao",
        "ming", "chao", "xia", "ping", "gang", "wen", "hua", "yong",
    ]
    base = rng.choice(PINYIN_NAMES) + rng.choice(PINYIN_NAMES)
    variants = [
        base,
        base + str(rng.randint(1, 999)),
        base + "_" + str(rng.randint(10, 99)),
    ]
    local = rng.choice(variants)
    domain = rng.choice(EMAIL_DOMAINS)
    return f"{local}@{domain}"


# ── Templates ──
# Each template is a function: (rng) -> (text, entities)
# {name}, {phone}, etc. are placeholders replaced with generated PII


@dataclass
class PII:
    text: str
    type: str
    start: int = 0
    end: int = 0


def _build(template: str, pii_map: dict[str, PII]) -> tuple[str, list[dict]]:
    """Replace placeholders in template and compute character offsets."""
    result = template
    entities = []

    # Sort by position in template (left to right) to handle offsets correctly
    placeholders = sorted(pii_map.keys(), key=lambda k: template.find(k))

    for ph in placeholders:
        pii = pii_map[ph]
        idx = result.find(ph)
        if idx == -1:
            continue
        result = result[:idx] + pii.text + result[idx + len(ph):]
        entities.append({
            "text": pii.text,
            "type": pii.type,
            "start": idx,
            "end": idx + len(pii.text),
        })

    return result, entities


TEMPLATE_FUNCS: list = []


def _t(fn):
    TEMPLATE_FUNCS.append(fn)
    return fn


@_t
def _tpl_basic_contact(rng):
    name = _gen_name(rng)
    phone = _gen_phone(rng)
    email = _gen_email(rng, name)
    return _build(
        rng.choice([
            "{name}的手机号是{phone}，邮箱{email}",
            "联系人：{name}，电话{phone}，邮箱：{email}",
            "请联系{name}，手机{phone}，或发邮件到{email}",
            "{name}同学的联系方式：{phone}，{email}",
        ]),
        {"{name}": PII(name, "person"), "{phone}": PII(phone, "phone"), "{email}": PII(email, "email")},
    )


@_t
def _tpl_id_and_phone(rng):
    name = _gen_name(rng)
    phone = _gen_phone(rng)
    id_num = _gen_id_number(rng)
    return _build(
        rng.choice([
            "客户{name}，身份证号{id}，联系电话{phone}",
            "{name}的身份证：{id}，手机号：{phone}",
            "姓名：{name}，证件号码：{id}，手机：{phone}",
            "核实{name}身份，身份证{id}，电话{phone}",
        ]),
        {"{name}": PII(name, "person"), "{id}": PII(id_num, "id_number"), "{phone}": PII(phone, "phone")},
    )


@_t
def _tpl_bank_card(rng):
    name = _gen_name(rng)
    card = _gen_bank_card(rng)
    phone = _gen_phone(rng)
    return _build(
        rng.choice([
            "{name}的银行卡号{card}，预留手机{phone}",
            "持卡人{name}，卡号：{card}，手机：{phone}",
            "转账至{name}账户，卡号{card}",
            "请核对{name}银行卡{card}的预留号码{phone}",
        ]),
        {"{name}": PII(name, "person"), "{card}": PII(card, "bank_card"), "{phone}": PII(phone, "phone")},
    )


@_t
def _tpl_address(rng):
    name = _gen_name(rng)
    addr = _gen_address(rng)
    phone = _gen_phone(rng)
    return _build(
        rng.choice([
            "{name}住在{addr}，电话{phone}",
            "收件人：{name}，地址：{addr}，电话：{phone}",
            "配送地址：{addr}，联系人{name}（{phone}）",
            "{name}的户籍地址为{addr}",
        ]),
        {"{name}": PII(name, "person"), "{addr}": PII(addr, "address"), "{phone}": PII(phone, "phone")},
    )


@_t
def _tpl_license_plate(rng):
    name = _gen_name(rng)
    plate = _gen_license_plate(rng)
    phone = _gen_phone(rng)
    return _build(
        rng.choice([
            "车主{name}，车牌号{plate}，电话{phone}",
            "{name}名下车辆{plate}",
            "违章车辆{plate}，车主联系电话{phone}",
            "登记人：{name}，车牌：{plate}，手机：{phone}",
        ]),
        {"{name}": PII(name, "person"), "{plate}": PII(plate, "license_plate"), "{phone}": PII(phone, "phone")},
    )


@_t
def _tpl_passport(rng):
    name = _gen_name(rng)
    passport = _gen_passport(rng)
    phone = _gen_phone(rng)
    return _build(
        rng.choice([
            "旅客{name}，护照号{passport}，联系电话{phone}",
            "{name}的护照号码：{passport}",
            "出入境旅客{name}，证件号{passport}，手机{phone}",
            "签证申请人：{name}，护照{passport}",
        ]),
        {"{name}": PII(name, "person"), "{passport}": PII(passport, "passport"), "{phone}": PII(phone, "phone")},
    )


@_t
def _tpl_full_registration(rng):
    name = _gen_name(rng)
    id_num = _gen_id_number(rng)
    phone = _gen_phone(rng)
    email = _gen_email(rng, name)
    addr = _gen_address(rng)
    return _build(
        rng.choice([
            "注册信息：{name}，身份证{id}，手机{phone}，邮箱{email}，地址{addr}",
            "用户{name}完成实名认证，身份证号{id}，绑定手机{phone}，邮箱{email}，居住地{addr}",
        ]),
        {
            "{name}": PII(name, "person"),
            "{id}": PII(id_num, "id_number"),
            "{phone}": PII(phone, "phone"),
            "{email}": PII(email, "email"),
            "{addr}": PII(addr, "address"),
        },
    )


@_t
def _tpl_multi_person(rng):
    name1 = _gen_name(rng)
    name2 = _gen_name(rng)
    phone1 = _gen_phone(rng)
    phone2 = _gen_phone(rng)
    return _build(
        rng.choice([
            "{name1}（{phone1}）和{name2}（{phone2}）是本次项目的负责人",
            "参会人员：{name1}，电话{phone1}；{name2}，电话{phone2}",
            "{name1}将工作交接给{name2}，联系方式分别是{phone1}和{phone2}",
        ]),
        {
            "{name1}": PII(name1, "person"),
            "{name2}": PII(name2, "person"),
            "{phone1}": PII(phone1, "phone"),
            "{phone2}": PII(phone2, "phone"),
        },
    )


@_t
def _tpl_medical(rng):
    name = _gen_name(rng)
    id_num = _gen_id_number(rng)
    phone = _gen_phone(rng)
    return _build(
        rng.choice([
            "患者{name}，身份证{id}，联系电话{phone}，因头痛就诊",
            "挂号信息：{name}，证件号{id}，手机{phone}",
            "病历号XXX，患者{name}，身份证号{id}，家属电话{phone}",
        ]),
        {"{name}": PII(name, "person"), "{id}": PII(id_num, "id_number"), "{phone}": PII(phone, "phone")},
    )


@_t
def _tpl_financial(rng):
    name = _gen_name(rng)
    card = _gen_bank_card(rng)
    id_num = _gen_id_number(rng)
    return _build(
        rng.choice([
            "开户人{name}，身份证{id}，银行卡号{card}",
            "{name}申请贷款，身份证号{id}，还款卡号{card}",
            "理财客户{name}，证件号{id}，绑定银行卡{card}",
        ]),
        {"{name}": PII(name, "person"), "{id}": PII(id_num, "id_number"), "{card}": PII(card, "bank_card")},
    )


@_t
def _tpl_delivery(rng):
    name = _gen_name(rng)
    phone = _gen_phone(rng)
    addr = _gen_address(rng)
    return _build(
        rng.choice([
            "快递单号SF1234567890，收件人{name}，{phone}，{addr}",
            "外卖订单：{name}，电话{phone}，送达地址{addr}",
            "寄件人：{name}，联系方式{phone}，取件地址：{addr}",
        ]),
        {"{name}": PII(name, "person"), "{phone}": PII(phone, "phone"), "{addr}": PII(addr, "address")},
    )


# ── Generator ──

def generate(count: int = 5000, seed: int = 42) -> list[dict]:
    """Generate `count` labeled Chinese PII samples."""
    rng = random.Random(seed)
    samples = []

    for i in range(count):
        tpl_fn = rng.choice(TEMPLATE_FUNCS)
        text, entities = tpl_fn(rng)

        # Verify offsets
        for ent in entities:
            actual = text[ent["start"]:ent["end"]]
            assert actual == ent["text"], (
                f"Offset mismatch: expected '{ent['text']}' at [{ent['start']}:{ent['end']}], "
                f"got '{actual}'"
            )

        samples.append({
            "id": f"zh_{i:06d}",
            "text": text,
            "lang": "zh",
            "entities": entities,
        })

    return samples


def main():
    parser = argparse.ArgumentParser(description="Generate Chinese PII benchmark data")
    parser.add_argument("--count", type=int, default=5000, help="Number of samples")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--output", default="-", help="Output file (- for stdout)")
    args = parser.parse_args()

    samples = generate(count=args.count, seed=args.seed)

    out = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")
    try:
        for sample in samples:
            out.write(json.dumps(sample, ensure_ascii=False) + "\n")
    finally:
        if out is not sys.stdout:
            out.close()

    if args.output != "-":
        print(f"Generated {len(samples)} samples → {args.output}", file=sys.stderr)

        # Print stats
        type_counts: dict[str, int] = {}
        for s in samples:
            for e in s["entities"]:
                type_counts[e["type"]] = type_counts.get(e["type"], 0) + 1
        print("Entity distribution:", file=sys.stderr)
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"  {t:<15s} {c:>6d}", file=sys.stderr)


if __name__ == "__main__":
    main()
