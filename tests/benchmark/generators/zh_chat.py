"""Chinese chat/IM noise benchmark generator.

Generates realistic Chinese chat messages with PII embedded in noisy,
informal contexts: voice-to-text, emoji, mixed zh/en, abbreviations,
non-standard formatting, casual tone.

Usage:
    python -m tests.benchmark.generators.zh_chat --count 3000 --output pii_bench_zh_chat.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import string
import sys
from dataclasses import dataclass

# Import from canonical source (specs/fakers_zh.py)
from argus_redact.specs.fakers_zh import (
    BANK_BINS,
    EMAIL_DOMAINS,
    GIVEN_NAMES,
    PLATE_PREFIXES,
    SURNAMES,
    fake_bank_card as _gen_bank_card,
    fake_id_number as _gen_id_number,
    fake_license_plate as _gen_license_plate,
    fake_passport as _gen_passport,
    fake_person_name_only as _gen_name,
    fake_phone as _gen_phone,
)


# ── Noise injection helpers ──

EMOJIS = [
    "😂", "🤣", "😅", "👍", "🙏", "❤️", "😊", "🤔", "💰", "📱",
    "🏠", "🚗", "✅", "⚠️", "🔥", "😭", "🤝", "👋", "📞", "💳",
]

FILLERS = [
    "嗯", "呃", "那个", "就是", "然后", "好的", "行", "嗯嗯", "哦",
    "ok", "OK", "好吧", "emmm", "额", "唔", "诶", "哈哈", "嘿",
]

CHAT_PUNCTUATION = ["~", "～", "！", "？", "。。。", "...", "…", "!!", "??", "hhh", "haha"]


def _add_noise(rng: random.Random, text: str) -> str:
    """Randomly inject noise into text."""
    # Maybe add emoji
    if rng.random() < 0.3:
        emoji = rng.choice(EMOJIS)
        pos = rng.choice(["start", "end", "mid"])
        if pos == "start":
            text = emoji + " " + text
        elif pos == "end":
            text = text + " " + emoji
        else:
            mid = len(text) // 2
            text = text[:mid] + emoji + text[mid:]

    # Maybe add filler word
    if rng.random() < 0.2:
        filler = rng.choice(FILLERS)
        text = filler + "，" + text

    # Maybe swap punctuation
    if rng.random() < 0.2:
        punct = rng.choice(CHAT_PUNCTUATION)
        text = text.rstrip("。，") + punct

    return text


def _phone_with_noise(rng: random.Random, phone: str) -> str:
    """Add realistic noise to phone number."""
    fmt = rng.choice(["clean", "spaced", "dashed", "cn_spaced"])
    if fmt == "spaced":
        return phone[:3] + " " + phone[3:7] + " " + phone[7:]
    elif fmt == "dashed":
        return phone[:3] + "-" + phone[3:7] + "-" + phone[7:]
    elif fmt == "cn_spaced":
        return phone[:3] + " " + phone[3:]
    return phone


def _id_with_noise(rng: random.Random, id_num: str) -> str:
    """Add realistic noise to ID number."""
    fmt = rng.choice(["clean", "spaced", "x_lower"])
    if fmt == "spaced":
        return id_num[:6] + " " + id_num[6:14] + " " + id_num[14:]
    elif fmt == "x_lower" and id_num[-1] == "X":
        return id_num[:-1] + "x"
    return id_num


# ── PII placeholder & builder (same pattern as zh.py) ──

@dataclass
class PII:
    text: str
    type: str
    start: int = 0
    end: int = 0


def _build(template: str, pii_map: dict[str, PII]) -> tuple[str, list[dict]]:
    result = template
    entities = []
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


# ── Chat templates ──

TEMPLATE_FUNCS: list = []


def _t(fn):
    TEMPLATE_FUNCS.append(fn)
    return fn


@_t
def _tpl_send_phone(rng):
    name = _gen_name(rng)
    phone = _phone_with_noise(rng, _gen_phone(rng))
    tpl = rng.choice([
        "{name}的电话 {phone}",
        "你存一下 {name} {phone}",
        "{name}手机号发你了 {phone}",
        "联系{name}打这个{phone}",
        "给{name}打电话 号码{phone}",
        "{phone} 这是{name}的号",
        "帮我打给{name} {phone} 谢谢",
        "{name}电话{phone} 你打一下",
    ])
    return _build(tpl, {"{name}": PII(name, "person"), "{phone}": PII(phone, "phone")})


@_t
def _tpl_send_id(rng):
    name = _gen_name(rng)
    id_num = _id_with_noise(rng, _gen_id_number(rng))
    tpl = rng.choice([
        "{name}身份证号 {id}",
        "身份证{id} 名字{name}",
        "帮{name}查一下 身份证号码{id}",
        "{name}的证件号码：{id}",
        "这个人叫{name} 身份证{id}",
        "报名信息 {name} {id}",
    ])
    return _build(tpl, {"{name}": PII(name, "person"), "{id}": PII(id_num, "id_number")})


@_t
def _tpl_send_card(rng):
    name = _gen_name(rng)
    card = _gen_bank_card(rng)
    tpl = rng.choice([
        "转账到{name}的卡 {card}",
        "{card} {name}的银行卡",
        "卡号{card} 户名{name}",
        "打钱到这个卡{card} {name}的",
        "帮我转到{name} 卡号{card}",
    ])
    return _build(tpl, {"{name}": PII(name, "person"), "{card}": PII(card, "bank_card")})


@_t
def _tpl_send_email(rng):
    name = _gen_name(rng)
    base = rng.choice(["wang", "li", "zhang", "chen"]) + rng.choice(["wei", "fang", "jie"])
    email = base + str(rng.randint(1, 99)) + "@" + rng.choice(EMAIL_DOMAINS)
    tpl = rng.choice([
        "{name}的邮箱 {email}",
        "发到{email} 是{name}的",
        "邮件发给{name} {email}",
        "cc一下{name} 邮箱是{email}",
        "联系{name}发邮件 地址{email}",
    ])
    return _build(tpl, {"{name}": PII(name, "person"), "{email}": PII(email, "email")})


@_t
def _tpl_voice_to_text(rng):
    """Simulate voice-to-text style — numbers spelled out or broken."""
    phone = _gen_phone(rng)
    name = _gen_name(rng)
    tpl = rng.choice([
        "那个{name}的电话号码是{phone}你记一下",
        "{name}电话{phone}帮我存一下谢谢",
        "我刚问了{name}说他号码是{phone}",
        "你问一下{name}电话{phone}能不能接",
    ])
    return _build(tpl, {"{name}": PII(name, "person"), "{phone}": PII(phone, "phone")})


@_t
def _tpl_mixed_zh_en(rng):
    """Chinese-English code-switching."""
    name = _gen_name(rng)
    phone = _gen_phone(rng)
    email_local = rng.choice(["test", "info", "admin"]) + str(rng.randint(1, 99))
    email = email_local + "@" + rng.choice(EMAIL_DOMAINS)
    tpl = rng.choice([
        "pls contact {name} phone:{phone} email:{email}",
        "{name}的contact info: {phone}, {email}",
        "FYI {name} {phone} email {email}",
        "help me reach {name} at {phone} or {email} thx",
    ])
    return _build(tpl, {
        "{name}": PII(name, "person"),
        "{phone}": PII(phone, "phone"),
        "{email}": PII(email, "email"),
    })


@_t
def _tpl_address_casual(rng):
    """Casual address sharing."""
    name = _gen_name(rng)
    phone = _gen_phone(rng)
    # Simple informal address
    districts = ["朝阳", "海淀", "浦东", "南山", "天河", "西湖", "武侯", "鼓楼"]
    streets = ["建国路", "中关村", "南京东路", "深南大道", "天府大道", "西溪路"]
    district = rng.choice(districts)
    street = rng.choice(streets)
    num = rng.randint(1, 200)
    addr = f"{district}{street}{num}号"
    tpl = rng.choice([
        "快递寄到{addr} {name} {phone}",
        "地址{addr} 收件人{name} 电话{phone}",
        "{name}在{addr} 电话{phone}",
        "外卖送到{addr} 联系{name}{phone}",
    ])
    return _build(tpl, {
        "{name}": PII(name, "person"),
        "{phone}": PII(phone, "phone"),
        "{addr}": PII(addr, "address"),
    })


@_t
def _tpl_plate_casual(rng):
    plate = _gen_license_plate(rng)
    phone = _gen_phone(rng)
    tpl = rng.choice([
        "挡路了 车牌{plate} 打电话{phone}叫他挪车",
        "{plate}这个车剐蹭了 车主电话{phone}",
        "你看下{plate}是谁的 让他打{phone}",
        "停车场{plate} 联系电话{phone}",
    ])
    return _build(tpl, {"{plate}": PII(plate, "license_plate"), "{phone}": PII(phone, "phone")})


@_t
def _tpl_multi_person_chat(rng):
    """Group chat with multiple people's info."""
    name1 = _gen_name(rng)
    name2 = _gen_name(rng)
    phone1 = _gen_phone(rng)
    phone2 = _gen_phone(rng)
    tpl = rng.choice([
        "{name1}{phone1} {name2}{phone2} 这俩人的电话",
        "群里发一下 {name1}的号{phone1} {name2}的号{phone2}",
        "@all {name1} {phone1}，{name2} {phone2}",
    ])
    return _build(tpl, {
        "{name1}": PII(name1, "person"),
        "{name2}": PII(name2, "person"),
        "{phone1}": PII(phone1, "phone"),
        "{phone2}": PII(phone2, "phone"),
    })


@_t
def _tpl_passport_casual(rng):
    name = _gen_name(rng)
    passport = _gen_passport(rng)
    tpl = rng.choice([
        "{name}护照号{passport} 帮我订机票",
        "护照{passport} 名字{name}",
        "{name}的护照发你了 {passport}",
    ])
    return _build(tpl, {"{name}": PII(name, "person"), "{passport}": PII(passport, "passport")})


@_t
def _tpl_wechat_style(rng):
    """WeChat-like short messages."""
    phone = _gen_phone(rng)
    name = _gen_name(rng)
    tpl = rng.choice([
        "微信加{name} 手机号{phone}",
        "{name}微信同号 {phone}",
        "加个微信吧 {name} {phone}",
        "微信搜{phone}就是{name}",
    ])
    return _build(tpl, {"{name}": PII(name, "person"), "{phone}": PII(phone, "phone")})


@_t
def _tpl_noisy_full_info(rng):
    """All-in-one info dump with noise."""
    name = _gen_name(rng)
    phone = _phone_with_noise(rng, _gen_phone(rng))
    id_num = _gen_id_number(rng)
    card = _gen_bank_card(rng)
    tpl = rng.choice([
        "{name} 手机{phone} 身份证{id} 银行卡{card} 都在这了",
        "信息汇总：{name}/{phone}/{id}/{card}",
        "发你了 {name} {phone} {id} {card}",
    ])
    return _build(tpl, {
        "{name}": PII(name, "person"),
        "{phone}": PII(phone, "phone"),
        "{id}": PII(id_num, "id_number"),
        "{card}": PII(card, "bank_card"),
    })


# ── Generator ──

def generate(count: int = 3000, seed: int = 42) -> list[dict]:
    rng = random.Random(seed)
    samples = []

    for i in range(count):
        tpl_fn = rng.choice(TEMPLATE_FUNCS)
        text, entities = tpl_fn(rng)

        # Apply noise to the text (only to non-PII parts to preserve offsets)
        # We add noise prefix/suffix instead
        noisy_text = _add_noise(rng, text)

        # Recalculate offsets if noise was added at start
        if noisy_text != text:
            offset = noisy_text.find(text[:20])
            if offset > 0:
                for ent in entities:
                    ent["start"] += offset
                    ent["end"] += offset
                text = noisy_text
            elif offset == 0:
                text = noisy_text
            # If we can't find the original text, skip noise
            # (mid-insertion case — just use original)

        # Verify offsets
        valid = True
        for ent in entities:
            actual = text[ent["start"]:ent["end"]]
            if actual != ent["text"]:
                valid = False
                break

        if not valid:
            # Fallback: regenerate without noise
            text_orig, entities = tpl_fn(rng)
            text = text_orig
            for ent in entities:
                assert text[ent["start"]:ent["end"]] == ent["text"]

        samples.append({
            "id": f"zh_chat_{i:06d}",
            "text": text,
            "lang": "zh",
            "entities": entities,
        })

    return samples


def main():
    parser = argparse.ArgumentParser(description="Generate Chinese chat PII benchmark data")
    parser.add_argument("--count", type=int, default=3000, help="Number of samples")
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
        type_counts: dict[str, int] = {}
        for s in samples:
            for e in s["entities"]:
                type_counts[e["type"]] = type_counts.get(e["type"], 0) + 1
        print("Entity distribution:", file=sys.stderr)
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"  {t:<15s} {c:>6d}", file=sys.stderr)


if __name__ == "__main__":
    main()
