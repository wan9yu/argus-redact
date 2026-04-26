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
import sys
from dataclasses import dataclass

# ── Import data pools and faker functions from canonical source ──
from argus_redact.specs.fakers_zh import (
    EMAIL_DOMAINS,
    PINYIN_PARTS,
    PROVINCES,
    STREETS,
)
from argus_redact.specs.fakers_zh import (
    fake_bank_card as _gen_bank_card,
)
from argus_redact.specs.fakers_zh import (
    fake_id_number as _gen_id_number,
)
from argus_redact.specs.fakers_zh import (
    fake_license_plate as _gen_license_plate,
)
from argus_redact.specs.fakers_zh import (
    fake_passport as _gen_passport,
)
from argus_redact.specs.fakers_zh import (
    fake_person_name_only as _gen_name,
)
from argus_redact.specs.fakers_zh import (
    fake_phone as _gen_phone,
)


def _gen_address(rng: random.Random) -> str:
    """Address with building/room (richer than the spec faker)."""
    province, city, districts = rng.choice(PROVINCES)
    district = rng.choice(districts)
    street = rng.choice(STREETS)
    number = rng.randint(1, 999)
    building = rng.randint(1, 30)
    room = rng.randint(101, 2505)
    return f"{province}{city}{district}{street}{number}号{building}栋{room}室"


def _gen_email(rng: random.Random, name: str) -> str:
    """Generate email with a random local part."""
    base = rng.choice(PINYIN_PARTS) + rng.choice(PINYIN_PARTS)
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
        result = result[:idx] + pii.text + result[idx + len(ph) :]
        entities.append(
            {
                "text": pii.text,
                "type": pii.type,
                "start": idx,
                "end": idx + len(pii.text),
            }
        )

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
        rng.choice(
            [
                "{name}的手机号是{phone}，邮箱{email}",
                "联系人：{name}，电话{phone}，邮箱：{email}",
                "请联系{name}，手机{phone}，或发邮件到{email}",
                "{name}同学的联系方式：{phone}，{email}",
            ]
        ),
        {
            "{name}": PII(name, "person"),
            "{phone}": PII(phone, "phone"),
            "{email}": PII(email, "email"),
        },
    )


@_t
def _tpl_id_and_phone(rng):
    name = _gen_name(rng)
    phone = _gen_phone(rng)
    id_num = _gen_id_number(rng)
    return _build(
        rng.choice(
            [
                "客户{name}，身份证号{id}，联系电话{phone}",
                "{name}的身份证：{id}，手机号：{phone}",
                "姓名：{name}，证件号码：{id}，手机：{phone}",
                "核实{name}身份，身份证{id}，电话{phone}",
            ]
        ),
        {
            "{name}": PII(name, "person"),
            "{id}": PII(id_num, "id_number"),
            "{phone}": PII(phone, "phone"),
        },
    )


@_t
def _tpl_bank_card(rng):
    name = _gen_name(rng)
    card = _gen_bank_card(rng)
    phone = _gen_phone(rng)
    return _build(
        rng.choice(
            [
                "{name}的银行卡号{card}，预留手机{phone}",
                "持卡人{name}，卡号：{card}，手机：{phone}",
                "转账至{name}账户，卡号{card}",
                "请核对{name}银行卡{card}的预留号码{phone}",
            ]
        ),
        {
            "{name}": PII(name, "person"),
            "{card}": PII(card, "bank_card"),
            "{phone}": PII(phone, "phone"),
        },
    )


@_t
def _tpl_address(rng):
    name = _gen_name(rng)
    addr = _gen_address(rng)
    phone = _gen_phone(rng)
    return _build(
        rng.choice(
            [
                "{name}住在{addr}，电话{phone}",
                "收件人：{name}，地址：{addr}，电话：{phone}",
                "配送地址：{addr}，联系人{name}（{phone}）",
                "{name}的户籍地址为{addr}",
            ]
        ),
        {
            "{name}": PII(name, "person"),
            "{addr}": PII(addr, "address"),
            "{phone}": PII(phone, "phone"),
        },
    )


@_t
def _tpl_license_plate(rng):
    name = _gen_name(rng)
    plate = _gen_license_plate(rng)
    phone = _gen_phone(rng)
    return _build(
        rng.choice(
            [
                "车主{name}，车牌号{plate}，电话{phone}",
                "{name}名下车辆{plate}",
                "违章车辆{plate}，车主联系电话{phone}",
                "登记人：{name}，车牌：{plate}，手机：{phone}",
            ]
        ),
        {
            "{name}": PII(name, "person"),
            "{plate}": PII(plate, "license_plate"),
            "{phone}": PII(phone, "phone"),
        },
    )


@_t
def _tpl_passport(rng):
    name = _gen_name(rng)
    passport = _gen_passport(rng)
    phone = _gen_phone(rng)
    return _build(
        rng.choice(
            [
                "旅客{name}，护照号{passport}，联系电话{phone}",
                "{name}的护照号码：{passport}",
                "出入境旅客{name}，证件号{passport}，手机{phone}",
                "签证申请人：{name}，护照{passport}",
            ]
        ),
        {
            "{name}": PII(name, "person"),
            "{passport}": PII(passport, "passport"),
            "{phone}": PII(phone, "phone"),
        },
    )


@_t
def _tpl_full_registration(rng):
    name = _gen_name(rng)
    id_num = _gen_id_number(rng)
    phone = _gen_phone(rng)
    email = _gen_email(rng, name)
    addr = _gen_address(rng)
    return _build(
        rng.choice(
            [
                "注册信息：{name}，身份证{id}，手机{phone}，邮箱{email}，地址{addr}",
                "用户{name}完成实名认证，身份证号{id}，绑定手机{phone}，邮箱{email}，居住地{addr}",
            ]
        ),
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
        rng.choice(
            [
                "{name1}（{phone1}）和{name2}（{phone2}）是本次项目的负责人",
                "参会人员：{name1}，电话{phone1}；{name2}，电话{phone2}",
                "{name1}将工作交接给{name2}，联系方式分别是{phone1}和{phone2}",
            ]
        ),
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
        rng.choice(
            [
                "患者{name}，身份证{id}，联系电话{phone}，因头痛就诊",
                "挂号信息：{name}，证件号{id}，手机{phone}",
                "病历号XXX，患者{name}，身份证号{id}，家属电话{phone}",
            ]
        ),
        {
            "{name}": PII(name, "person"),
            "{id}": PII(id_num, "id_number"),
            "{phone}": PII(phone, "phone"),
        },
    )


@_t
def _tpl_financial(rng):
    name = _gen_name(rng)
    card = _gen_bank_card(rng)
    id_num = _gen_id_number(rng)
    return _build(
        rng.choice(
            [
                "开户人{name}，身份证{id}，银行卡号{card}",
                "{name}申请贷款，身份证号{id}，还款卡号{card}",
                "理财客户{name}，证件号{id}，绑定银行卡{card}",
            ]
        ),
        {
            "{name}": PII(name, "person"),
            "{id}": PII(id_num, "id_number"),
            "{card}": PII(card, "bank_card"),
        },
    )


@_t
def _tpl_delivery(rng):
    name = _gen_name(rng)
    phone = _gen_phone(rng)
    addr = _gen_address(rng)
    return _build(
        rng.choice(
            [
                "快递单号SF1234567890，收件人{name}，{phone}，{addr}",
                "外卖订单：{name}，电话{phone}，送达地址{addr}",
                "寄件人：{name}，联系方式{phone}，取件地址：{addr}",
            ]
        ),
        {
            "{name}": PII(name, "person"),
            "{phone}": PII(phone, "phone"),
            "{addr}": PII(addr, "address"),
        },
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
            actual = text[ent["start"] : ent["end"]]
            assert actual == ent["text"], (
                f"Offset mismatch: expected '{ent['text']}' at [{ent['start']}:{ent['end']}], "
                f"got '{actual}'"
            )

        samples.append(
            {
                "id": f"zh_{i:06d}",
                "text": text,
                "lang": "zh",
                "entities": entities,
            }
        )

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
