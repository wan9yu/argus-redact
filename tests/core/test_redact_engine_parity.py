"""Master parity for the replace/restore/faker engine (v0.7.3 port).

Freezes whole-pipeline redact() output — (redacted, key) — over a corpus
spanning every strategy (mask/name_mask/landline_mask/pseudonym/remove/keep/
category/realistic) at fixed salt. Prior parity tests don't exercise
replace/realistic; this is the linchpin for the Rust engine port.

Adjustments from the original plan corpus (noted inline):
- zh_name_mask / zh_collision: added names=[...] because standalone Chinese
  names are not detected in fast mode without the names= hint.
- zh_category: changed type from "location" (undetected in fast mode) to
  "address", and text to one where fast-mode detects an address span.
"""

import json
from pathlib import Path

from argus_redact import redact

FIXTURE = Path(__file__).parent / "fixtures" / "redact_engine_v072.json"
SALT = 42  # fixed → deterministic pseudonym + faker derivation

# (label, text, lang, config, names)
# names=None means no names= kwarg passed (fast mode won't detect bare Chinese names)
CASES = [
    ("zh_default", "张三的电话13812345678，身份证110101199003074610", "zh", None, None),
    (
        "zh_realistic",
        "张三的电话13812345678，身份证110101199003074610",
        "zh",
        {
            "person": {"strategy": "realistic"},
            "phone": {"strategy": "realistic"},
            "id_number": {"strategy": "realistic"},
        },
        None,
    ),
    (
        "zh_mask",
        "电话13812345678 银行卡6217000000000000",
        "zh",
        {"phone": {"strategy": "mask"}, "bank_card": {"strategy": "mask"}},
        None,
    ),
    (
        "zh_landline_mask",
        "座机 010-12345678",
        "zh",
        {"phone_landline": {"strategy": "landline_mask"}, "phone": {"strategy": "landline_mask"}},
        None,
    ),
    # names= required: standalone Chinese names not detected in fast mode
    (
        "zh_name_mask",
        "张三和欧阳明",
        "zh",
        {"person": {"strategy": "name_mask"}},
        ["张三", "欧阳明"],
    ),
    # original plan used "location" type + "我在北京市朝阳区" — neither detected in fast mode.
    # Changed to "address" type with a text where the address span is detected.
    ("zh_category", "北京市朝阳区三里屯", "zh", {"address": {"strategy": "category"}}, None),
    ("zh_keep", "我妈说她13812345678", "zh", None, None),
    # names= required; repeated entity reuses one mask (no circled suffix needed)
    (
        "zh_collision",
        "张三 张三 李四 张三",
        "zh",
        {"person": {"strategy": "name_mask"}},
        ["张三", "李四"],
    ),
    (
        "en_realistic",
        "John Smith SSN 123-45-6789 card 4111111111111111",
        "en",
        {
            "person": {"strategy": "realistic"},
            "ssn": {"strategy": "realistic"},
            "credit_card": {"strategy": "realistic"},
        },
        None,
    ),
    (
        "en_address",
        "lives at 1600 Pennsylvania Ave",
        "en",
        {"address": {"strategy": "realistic"}},
        None,
    ),
    ("shared_email_ip", "mail a@b.com from 8.8.8.8", "en", None, None),  # shared_via_en → en
    ("unified", "张三 13812345678 110101199003074610", "zh", None, None),
]


def _run(text, lang, config, names=None):
    kw = dict(mode="fast", lang=lang, salt=SALT, config=config)
    if names is not None:
        kw["names"] = names
    redacted, key = redact(text, **kw)
    return {"redacted": redacted, "key": dict(sorted(key.items()))}


def _build():
    snap = {}
    for label, text, lang, config, names in CASES:
        snap[label] = _run(text, lang, config, names=names)
    # one unified_prefix case via the kwarg
    r, k = redact(
        "张三 13812345678 110101199003074610", mode="fast", lang="zh", salt=SALT, unified_prefix="R"
    )
    snap["unified_prefix"] = {"redacted": r, "key": dict(sorted(k.items()))}
    return snap


def test_redact_engine_parity():
    current = _build()
    if not FIXTURE.exists():
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(
            json.dumps(current, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        raise AssertionError("Wrote v0.7.2 redact-engine snapshot — re-run to compare. COMMIT it.")
    frozen = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert current == frozen, "redact-engine output drift vs frozen v0.7.2"
