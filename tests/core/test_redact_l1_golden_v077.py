"""Frozen golden for the fast-mode L1 redact engine (pre-Rust-port safety net).

Task 1 of the v0.7.7 plan. Freezes two things at a fixed salt over one shared
corpus, so the later Rust port of the fast-mode L1 engine (detection
orchestration + the L1 hints + the 3 deferred validators) can prove byte-for-byte
equivalence:

  1. ``redact_l1_v077.json`` — whole-pipeline ``redact(mode="fast")`` output,
     ``{label: {redacted, key(sorted)}}``. ``redact()``'s default
     ``(redacted, key)`` return is the master gate (same convention as
     ``test_redact_engine_parity.py``).
  2. ``hints_l1_v077.json`` — the ``text_intent`` + ``self_reference_tier`` L1
     hints per case, captured with the EXACT inputs the pipeline feeds
     ``produce_hints`` (the L1a ``match_patterns`` entities + near-misses, on
     the same patterns ``_detect`` loads via ``_load_patterns``).

The corpus reuses the 12 CASES + ``unified_prefix`` from
``test_redact_engine_parity.py`` verbatim, then adds engineered cases that
exercise the v0.7.7 NEW code paths (text_intent x4, self-reference tiers x3, a
person-threshold flip, the jwt/organization/school deferred validators incl.
accept + reject, a near-miss-bearing text, a multi-byte/emoji prefix, a
known_names case, and two redact->restore round-trips for the cross-language
alias path).

Regenerate (only when the change in behavior is intended and reviewed)::

    python -m argus_redact  # not this; use the block below
    python tests/core/test_redact_l1_golden_v077.py

which rewrites BOTH fixtures from the current Python pipeline.
"""
import json
from pathlib import Path

import pytest

from argus_redact import redact, restore
from argus_redact.glue.redact import _load_patterns
from argus_redact.pure.hints import produce_hints
from argus_redact.pure.patterns import match_patterns

FIXTURE_REDACT = Path(__file__).parent / "fixtures" / "redact_l1_v077.json"
FIXTURE_HINTS = Path(__file__).parent / "fixtures" / "hints_l1_v077.json"
SALT = 42  # fixed → deterministic pseudonym + faker derivation

# A real, validator-accepted JWT: header {"alg":"HS256"} . payload {"sub":"123"} . sig
_JWT_VALID = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
# 2 segments → rejected by len(parts)!=3 (regex needs 3, so not even detected).
_JWT_INVALID_2SEG = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ"
# 3 segments, but header {"typ":"JWT"} has no "alg" → validator rejects → near-miss.
_JWT_INVALID_NOALG = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjMifQ.sig"

# (label, text, lang, config, names, unified_prefix)
# names=None → no names= kwarg. unified_prefix=None → no unified_prefix= kwarg.
# The first 12 + unified_prefix mirror test_redact_engine_parity.py verbatim.
CASES = [
    # ── 12 reused engine-parity CASES (verbatim) ──
    ("zh_default", "张三的电话13812345678，身份证110101199003074610", "zh", None, None, None),
    ("zh_realistic", "张三的电话13812345678，身份证110101199003074610",
        "zh", {"person": {"strategy": "realistic"}, "phone": {"strategy": "realistic"},
               "id_number": {"strategy": "realistic"}}, None, None),
    ("zh_mask", "电话13812345678 银行卡6217000000000000", "zh",
        {"phone": {"strategy": "mask"}, "bank_card": {"strategy": "mask"}}, None, None),
    ("zh_landline_mask", "座机 010-12345678", "zh",
        {"phone_landline": {"strategy": "landline_mask"}, "phone": {"strategy": "landline_mask"}},
        None, None),
    ("zh_name_mask", "张三和欧阳明", "zh", {"person": {"strategy": "name_mask"}},
        ["张三", "欧阳明"], None),
    ("zh_category", "北京市朝阳区三里屯", "zh", {"address": {"strategy": "category"}}, None, None),
    ("zh_keep", "我妈说她13812345678", "zh", None, None, None),
    ("zh_collision", "张三 张三 李四 张三", "zh", {"person": {"strategy": "name_mask"}},
        ["张三", "李四"], None),
    ("en_realistic", "John Smith SSN 123-45-6789 card 4111111111111111", "en",
        {"person": {"strategy": "realistic"}, "ssn": {"strategy": "realistic"},
         "credit_card": {"strategy": "realistic"}}, None, None),
    ("en_address", "lives at 1600 Pennsylvania Ave", "en",
        {"address": {"strategy": "realistic"}}, None, None),
    ("shared_email_ip", "mail a@b.com from 8.8.8.8", "en", None, None, None),
    ("unified", "张三 13812345678 110101199003074610", "zh", None, None, None),
    # unified_prefix kwarg case (mirrors the parity test's separate snapshot entry)
    ("unified_prefix", "张三 13812345678 110101199003074610", "zh", None, None, "R"),

    # ── text_intent x4 (drives the zh person threshold) ──
    # instruction (zh command prefix 帮我) — should suppress a borderline name
    ("intent_instruction_zh", "帮我查一下张三的电话号码", "zh", None, None, None),
    # instruction (en command "Can you ... tell me ...")
    ("intent_instruction_en", "Can you tell me about John Smith?", "en", None, None, None),
    # narrative (self-ref absent, PII present)
    ("intent_narrative_zh", "张三的电话13812345678", "zh", None, None, None),
    # casual (self-ref present, no other PII, not a command)
    ("intent_casual_zh", "我今天很开心", "zh", None, None, None),
    # neutral (no self-ref, no PII)
    ("intent_neutral_zh", "今天天气不错", "zh", None, None, None),

    # ── self_reference tiers x3 ──
    # tier 1: kinship self-ref kept (我妈) alongside other PII
    ("selfref_tier1_kinship", "我妈说她的电话是13812345678", "zh", None, None, None),
    # tier 2: pronoun-only self-ref, no PII, no kinship, not a command
    ("selfref_tier2_pronoun", "我在这里", "zh", None, None, None),
    # tier 3: interaction-command self-ref, no kinship, no PII
    ("selfref_tier3_command", "帮我看看我说的对不对", "zh", None, None, None),

    # ── person-threshold flip (same borderline name, two phrasings) ──
    # instruction-intent (threshold 1.2) suppresses 王芳
    ("threshold_flip_instruction", "帮我查一下王芳的资料", "zh", None, None, None),
    # narrative-intent (threshold 0.8) keeps 王芳
    ("threshold_flip_narrative", "王芳的电话是13812345678", "zh", None, None, None),

    # ── deferred validators: jwt / organization / school (Task 2 Rust port) ──
    # valid jwt → detected
    ("jwt_valid", f"token is {_JWT_VALID}", "en", None, None, None),
    # 2-segment jwt → not detected (regex requires 3 segments; no near-miss)
    ("jwt_invalid_2seg", f"token is {_JWT_INVALID_2SEG}", "en", None, None, None),
    # 3-segment jwt, header lacks "alg" → validator rejects → near-miss, not detected
    ("jwt_invalid_noalg", f"token is {_JWT_INVALID_NOALG}", "en", None, None, None),
    # zh organization → detected
    ("org_valid", "我在阿里巴巴有限公司上班", "zh", None, None, None),
    # near-miss org: regex matches "这是公司" but validator rejects (no name before suffix)
    ("org_nearmiss", "这是公司", "zh", None, None, None),
    # zh school → detected
    ("school_valid", "我毕业于北京大学", "zh", None, None, None),
    # near-miss school: regex matches "这是大学" but validator rejects
    ("school_nearmiss", "这是大学", "zh", None, None, None),

    # ── misc edge cases ──
    # multi-byte / emoji-prefixed text (offset mapping over a 4-byte prefix)
    ("emoji_prefix", "🎉张三的电话13812345678", "zh", None, ["张三"], None),
    # near-miss-bearing text: an id-shaped string that fails checksum validation
    ("near_miss_id", "身份证110101199003074611", "zh", None, None, None),
    # known_names: multi-char surnames only detectable via names= hint
    ("known_names", "欧阳明和司马光开会", "zh", None, ["欧阳明", "司马光"], None),

    # ── redact→restore round-trips (exercise the cross-language alias path) ──
    # zh name, realistic strategy, en-first lang order → English faker name;
    # restore() recovers the original (key maps fake→original).
    ("roundtrip_en_faker", "张三给我发了邮件", ["en", "zh"],
        {"person": {"strategy": "realistic"}}, ["张三"], None),
    # zh name, realistic strategy, default zh lang; restore round-trips a phone too.
    ("roundtrip_zh_realistic", "张三的电话13812345678", "zh",
        {"person": {"strategy": "realistic"}}, ["张三"], None),
]

# Round-trip cases additionally assert restore() recovers the original.
_ROUNDTRIP = {
    "roundtrip_en_faker": "张三给我发了邮件",
    "roundtrip_zh_realistic": "张三的电话13812345678",
}


def _run_redact(text, lang, config, names, unified_prefix):
    kw = dict(mode="fast", lang=lang, salt=SALT, config=config)
    if names is not None:
        kw["names"] = names
    if unified_prefix is not None:
        kw["unified_prefix"] = unified_prefix
    redacted, key = redact(text, **kw)
    return {"redacted": redacted, "key": dict(sorted(key.items()))}


def _capture_hints(text, lang):
    """Reconstruct the L1 hints the way the pipeline does.

    Mirrors glue/redact.py:_detect — ``match_patterns(detect_text, _load_patterns(lang))``
    yields the L1a entities + near-misses, then
    ``produce_hints(layer1, text, near_misses=near_misses)``. Only ``layer1`` is
    needed for text_intent / self_reference_tier (the self_reference entities come
    from the L1a regex match itself). We serialize ONLY those two hint types.

    Note: ``_detect`` normalizes text and maps spans back before calling
    produce_hints; for these corpus inputs no normalization span shift affects the
    text_intent/self_reference hints (text_intent is global (0,0); self_reference
    regions are over the original text). Captured on the un-normalized text to match
    the typical fast path; the golden pins whatever the current code produces.
    """
    layer1, near_misses = match_patterns(text, _load_patterns(lang))
    hints = produce_hints(layer1, text, near_misses=near_misses)
    l1_hints = [h for h in hints if h.type in ("text_intent", "self_reference_tier")]
    return [
        {
            "type": h.type,
            "data": h.data,
            "region": [h.region[0], h.region[1]],
            "source_layer": h.source_layer,
        }
        for h in l1_hints
    ]


def _build_redact():
    return {
        label: _run_redact(text, lang, config, names, unified_prefix)
        for label, text, lang, config, names, unified_prefix in CASES
    }


def _build_hints():
    return {
        label: _capture_hints(text, lang)
        for label, text, lang, config, names, unified_prefix in CASES
    }


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


_CASE_IDS = [c[0] for c in CASES]


def test_fixtures_present():
    """Guard: both fixtures load and are non-empty (an emptied fixture fails loudly)."""
    assert FIXTURE_REDACT.exists(), f"missing {FIXTURE_REDACT.name}"
    assert FIXTURE_HINTS.exists(), f"missing {FIXTURE_HINTS.name}"
    redact_golden = _load(FIXTURE_REDACT)
    hints_golden = _load(FIXTURE_HINTS)
    assert len(redact_golden) > 0, "redact golden is empty"
    assert len(hints_golden) > 0, "hints golden is empty"
    # Every corpus case must be present in both fixtures.
    assert set(redact_golden) == set(_CASE_IDS)
    assert set(hints_golden) == set(_CASE_IDS)


@pytest.mark.parametrize("label", _CASE_IDS)
def test_redact_golden(label):
    """Current Python redact(mode=fast) == frozen (redacted, key) per case."""
    golden = _load(FIXTURE_REDACT)[label]
    case = next(c for c in CASES if c[0] == label)
    _, text, lang, config, names, unified_prefix = case
    current = _run_redact(text, lang, config, names, unified_prefix)
    assert current == golden, f"redact drift for {label!r}"


@pytest.mark.parametrize("label", _CASE_IDS)
def test_hints_golden(label):
    """Current Python L1 hints == frozen text_intent + self_reference_tier per case."""
    golden = _load(FIXTURE_HINTS)[label]
    case = next(c for c in CASES if c[0] == label)
    _, text, lang, _config, _names, _prefix = case
    current = _capture_hints(text, lang)
    assert current == golden, f"L1 hint drift for {label!r}"


@pytest.mark.parametrize("label", sorted(_ROUNDTRIP))
def test_roundtrip_restore(label):
    """restore(redacted, key) recovers the original (cross-language alias path)."""
    case = next(c for c in CASES if c[0] == label)
    _, text, lang, config, names, unified_prefix = case
    kw = dict(mode="fast", lang=lang, salt=SALT, config=config)
    if names is not None:
        kw["names"] = names
    redacted, key = redact(text, **kw)
    assert restore(redacted, key) == text, f"round-trip failed for {label!r}"


def _regenerate():
    """Rewrite BOTH fixtures from the current Python pipeline. Run via __main__."""
    FIXTURE_REDACT.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_REDACT.write_text(
        json.dumps(_build_redact(), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    FIXTURE_HINTS.write_text(
        json.dumps(_build_hints(), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(f"Wrote {FIXTURE_REDACT.name} ({len(CASES)} cases)")
    print(f"Wrote {FIXTURE_HINTS.name} ({len(CASES)} cases)")


if __name__ == "__main__":
    _regenerate()
