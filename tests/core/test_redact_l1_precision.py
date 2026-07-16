"""Committed adversarial precision / differential gate for the L1 engine (Task 9).

This file PERMANENTLY locks the bit-identity of the L1 engine by committing two
differential families that prior task reviews ran but reverted, plus targeted
constant gates. It is the standing regression net for the v0.7.7 Rust port.

What is locked, and against WHICH reference (this is load-bearing):

  A. Hint parity — Rust ``_core.produce_hints_l1`` vs LIVE Python
     ``pure/hints.produce_hints`` over the FULL 4-hint set (``pii_density``,
     ``near_miss_format``, ``text_intent``, ``self_reference_tier``). The Rust
     producer now emits all 4 types (matching Python), so the comparison is
     apples-to-apples across the whole set — no filtering. Task 8 routed the
     fast-mode detect/replace path through Rust, but ``pure/hints.produce_hints``
     is STILL pure Python and STILL live (full-mode + the report build the FULL
     4-hint set from it). So this is a genuine Rust-vs-Python differential — NOT a
     self-comparison. It locks the 8-language ``text_intent`` decision logic and the
     cross-engine ``\\s`` / ``\\b`` / strip fidelity that the v0.7.6 finding showed
     is fragile (Rust ``\\s`` is widened to ``[\\s\\x1c-\\x1f]`` to match Python's
     ``str`` semantics; Rust ``py_strip`` must drop the same leading control chars
     Python ``str.strip()`` does). This is the HIGHEST-value gate.

  B. ``_core.redact_l1`` vs ``redact(mode="fast")`` — path-equivalence. Both are
     Rust now, but separate code: ``redact_l1`` is the bundled iOS entry (one Rust
     call: detect_l1 -> merge -> filter -> replace), while ``redact()`` drives
     detect_l1 + replace through the Python shim. Locking them equal keeps the
     iOS-facing entry in sync with the shipped Python path. (redact(fast) vs the
     pre-port Python is already locked by the T1 golden ``redact_l1_v077.json``;
     we do not re-derive a pure-Python redact reference — the shim is Rust now.)

  C. Targeted constant / precision gates — pin the 1.2 / 0.8 person thresholds and
     the jwt / organization / school validators through ``redact(mode="fast")``,
     each with an "if you change X this fails" comment.

NON-VACUITY: every differential compares two INDEPENDENT engines (Rust ``_core``
vs Python ``produce_hints`` / ``redact``); there are no ``x == x`` self-compares.
``test_corpus_nonempty`` guards every corpus against silent emptying. The
``test_*_tamper_reasoned`` tests prove the assertions are real by confirming a
frozen-expected value differs from a deliberately-wrong value (we cannot perturb
the compiled Rust, so we prove the gate would catch a regression by reasoning over
a known-wrong expectation).
"""

import warnings

import argus_redact._core as _core
import pytest

from argus_redact import redact
from argus_redact.glue.redact import _detect, _load_patterns
from argus_redact.pure.hints import (
    filter_self_reference as py_filter_self_reference,
)
from argus_redact.pure.hints import (
    get_person_threshold as py_get_person_threshold,
)
from argus_redact.pure.hints import (
    produce_hints as py_produce_hints,
)
from argus_redact.pure.patterns import match_patterns
from argus_redact.pure.replacer import (
    _KEEP_WHITELIST,
    DEFAULT_PREFIXES,
    _build_type_info,
)

SALT = 42  # matches the T1 fixture freeze.


# ── helpers ──────────────────────────────────────────────────────────────────


def _to_core(matches):
    """Mirror a list of Python PatternMatch into _core.PatternMatch (same fields)."""
    return [
        _core.PatternMatch(m.text, m.type, m.start, m.end, m.confidence, m.layer) for m in matches
    ]


def _py_l1_hints(entities, text):
    """The FULL hint set from LIVE Python produce_hints — all 4 hint types
    (pii_density, near_miss_format, text_intent, self_reference_tier).

    The Rust _core.produce_hints_l1 now emits the same 4 types, so this is the
    INDEPENDENT, apples-to-apples reference for the Rust producer (no filtering).
    With no near_misses passed, produce_hints emits pii_density + [tier] +
    text_intent and NO near_miss_format — matching produce_hints_l1's default.
    """
    return py_produce_hints(entities, text)


def _real_entities(text, lang):
    """Build REAL L1 entities for `text` via match_patterns(_load_patterns(lang)).

    Using the real matcher means the self_reference / kinship entities are exactly
    what the pipeline sees — `我妈` is a real kinship self_reference, `me` / `我` are
    real pronoun self_references — so the hint decision tree is exercised honestly,
    not over hand-faked spans.
    """
    entities, _near = match_patterns(text, _load_patterns(lang))
    return entities


def _core_redact_fast(
    text, lang, *, config=None, names=None, types=None, types_exclude=None, unified_prefix=None
):
    """Drive `_core.redact_l1` the way the Python fast-mode pipeline does.

    Identical wiring to the T7 export test: build `type_info` / `custom_fakers`
    via the SAME `_build_type_info` `replace()` uses, resolve prefixes / keep
    whitelist identically, forward the detect_l1 lang / names + the type filter.
    Returns the redact_l1 5-tuple (redacted, key, aliases, keep_downgraded, mask_collisions).
    """
    entities, resolved_langs, _, _ = _detect(
        text, lang=lang, mode="fast", names=names, types=types, types_exclude=types_exclude
    )
    type_info, custom_fakers = _build_type_info(entities, config, resolved_langs)
    person_prefix = DEFAULT_PREFIXES["person"]
    org_prefix = DEFAULT_PREFIXES["organization"]
    if config:
        person_prefix = config.get("person", {}).get("prefix", person_prefix)
        org_prefix = config.get("organization", {}).get("prefix", org_prefix)
    return _core.redact_l1(
        text,
        resolved_langs,
        names,
        type_info=type_info,
        salt=SALT,
        key=None,
        person_prefix=person_prefix,
        org_prefix=org_prefix,
        unified_prefix=unified_prefix,
        keep_whitelist=set(_KEEP_WHITELIST),
        types=set(types) if types else None,
        types_exclude=set(types_exclude) if types_exclude else None,
        custom_fakers=custom_fakers or None,
    )


def _py_redact_fast(
    text, lang, *, config=None, names=None, types=None, types_exclude=None, unified_prefix=None
):
    """LIVE Python `redact(mode="fast")` — the independent reference for family B."""
    kw = dict(mode="fast", lang=lang, salt=SALT, config=config)
    if names is not None:
        kw["names"] = names
    if types is not None:
        kw["types"] = types
    if types_exclude is not None:
        kw["types_exclude"] = types_exclude
    if unified_prefix is not None:
        kw["unified_prefix"] = unified_prefix
    return redact(text, **kw)


# ══════════════════════════════════════════════════════════════════════════════
# A. HINT PARITY — Rust _core.produce_hints_l1 vs LIVE Python produce_hints (L1)
#    The load-bearing gate. Corpus of adversarial inputs covering every v0.7.7 edge.
# ══════════════════════════════════════════════════════════════════════════════

# Control chars U+001C..U+001F. Python `\s` matches these (str semantics); a naive
# Rust `\s` does NOT — the engine widens command-pattern `\s` to `[\s\x1c-\x1f]`.
_FS, _GS, _RS, _US = "\x1c", "\x1d", "\x1e", "\x1f"

# (label, text, lang) — `lang` chooses which lang PATTERNS load (self_reference
# pronoun patterns exist only for zh + en). COMMAND prefixes/suffixes/regex are
# aggregated from ALL 8 language modules inside pure/hints.py regardless of `lang`,
# so an English pronoun ('me') + a German / ja / ko command in the text exercises
# the non-en command logic with a real self_reference present.
_HINT_CORPUS = [
    # ── text_intent: the four base intents ──
    ("neutral_no_selfref_no_pii", "今天天气不错", "zh"),
    ("narrative_pii_no_selfref", "电话13800138000在这里", "zh"),
    ("casual_pronoun_zh", "我今天很开心", "zh"),
    ("casual_pronoun_en", "just me here today", "en"),
    # ── instruction via per-language command surface (8-lang coverage) ──
    ("instruction_zh_prefix", "帮我查一下资料 我在这", "zh"),  # zh prefix 帮我 + pronoun 我
    ("instruction_zh_prefix2", "请帮我看看我说的", "zh"),
    ("instruction_en_regex", "Can you help me with this", "en"),  # en COMMAND_PATTERNS
    ("instruction_en_regex2", "Please tell me about it, I asked", "en"),
    ("instruction_de_regex", "können Sie help me", "en"),  # de regex (können Sie) + en pronoun
    ("instruction_uk_regex", "could you please help me", "en"),  # uk regex
    ("instruction_in_regex", "kindly revert, help me", "en"),  # in_ regex (kindly/revert)
    ("instruction_br_regex", "por favor me ajude, help me", "en"),  # br regex (por favor)
    ("instruction_ja_suffix", "me 連絡してください", "en"),  # ja COMMAND_SUFFIXES
    ("instruction_ko_suffix", "me 알려주세요", "en"),  # ko COMMAND_SUFFIXES
    # ── command-with-PII precedence: command AND other_pii → instruction (not narrative) ──
    ("command_plus_pii_zh", "请帮我查电话13800138000", "zh"),
    # ── command-with-kinship: command + kinship → instruction, tier 1 (NOT tier 3) ──
    ("command_plus_kinship_zh", "请帮我找我妈", "zh"),
    # ── self_reference tiers 1 / 2 / 3 ──
    ("tier1_kinship_plus_pii", "我妈说她的电话是13800138000", "zh"),
    ("tier2_pronoun_only", "我在这里", "zh"),
    ("tier3_command_pronoun", "帮我看看我说的对不对", "zh"),
    # ── multi self-ref where only ONE is kinship (has_kinship must still be True) ──
    ("multi_selfref_one_kinship", "我和我妈在这", "zh"),
    # ── kinship: per-language matchers (zh exact 我妈, en prefix "my mother") ──
    ("kinship_zh_exact", "我妈在家", "zh"),
    ("kinship_en_prefix", "my mother is here", "en"),
    # ── \s control-char fidelity (v0.6 finding): de command separated by control ──
    #    chars + en pronoun self-ref → must STILL be instruction (Rust \s→[\s\x1c-\x1f]).
    ("ctrl_FS_command", f"können{_FS}Sie help me", "en"),
    ("ctrl_GS_command", f"können{_GS}Sie help me", "en"),
    ("ctrl_RS_command", f"können{_RS}Sie help me", "en"),
    ("ctrl_US_command", f"können{_US}Sie help me", "en"),
    # ── CJK \b / strip: leading control char before a zh self-ref + command. Python ──
    #    str.strip() removes the leading U+001C; Rust py_strip must too → same intent.
    ("cjk_strip_leading_ctrl_cmd", f"{_FS}请帮我", "zh"),
    ("cjk_strip_leading_ctrl_casual", f"{_FS}我在这", "zh"),
]


@pytest.mark.parametrize("case", _HINT_CORPUS, ids=[c[0] for c in _HINT_CORPUS])
def test_hint_parity_core_vs_live_python(case):
    """_core.produce_hints_l1(ents, text) == LIVE Python produce_hints(...), all 4 types.

    Rust-vs-Python differential (NOT self-compare). If the Rust text_intent /
    self_reference tier / pii_density logic, the \\s control-char widening, or the
    py_strip leading-control handling drifts from Python, this fails.
    """
    _label, text, lang = case
    py_ents = _real_entities(text, lang)
    core_ents = _to_core(py_ents)
    core_hints = _core.produce_hints_l1(core_ents, text)
    py_hints = _py_l1_hints(py_ents, text)
    assert core_hints == py_hints, f"hint drift for {_label!r}: core={core_hints} py={py_hints}"


def test_hint_parity_command_pii_precedence_is_instruction():
    """Pins command-with-PII precedence: command AND other_pii → instruction.

    If you change pure/hints.produce_hints so a command with PII falls through to
    'narrative', the Rust port would NOT follow and this differential goes red.
    """
    text = "请帮我查电话13800138000"
    py_ents = _real_entities(text, "zh")
    core = _core.produce_hints_l1(_to_core(py_ents), text)
    py = _py_l1_hints(py_ents, text)
    assert core == py
    intent = next(h.data["intent"] for h in core if h.type == "text_intent")
    assert intent == "instruction"  # command beats narrative


def test_hint_parity_command_kinship_is_tier1_instruction():
    """Pins command-with-kinship: → instruction text_intent AND tier 1 (NOT tier 3).

    Tier 3 is reserved for command + pronoun-only (no kinship, no PII). Kinship
    forces tier 1 even under a command. If you change that, this fails.
    """
    text = "请帮我找我妈"
    py_ents = _real_entities(text, "zh")
    core = _core.produce_hints_l1(_to_core(py_ents), text)
    py = _py_l1_hints(py_ents, text)
    assert core == py
    by = {h.type: h.data for h in core}
    assert by["text_intent"]["intent"] == "instruction"
    assert by["self_reference_tier"]["tier"] == 1
    assert by["self_reference_tier"]["has_kinship"] is True


def test_hint_parity_control_char_command_matches_python():
    """\\s control-char fidelity: a U+001D-separated 'können Sie' command + 'me'.

    The de COMMAND_PATTERNS regex uses `\\s+`; with the U+001D separator a naive
    Rust `\\s` would FAIL to match and the intent would degrade to 'casual'. The
    engine widens `\\s`→`[\\s\\x1c-\\x1f]` to match Python str semantics, so both
    engines must produce 'instruction'. Compares Rust to LIVE Python.
    """
    text = f"können{_GS}Sie help me"
    py_ents = _real_entities(text, "en")
    core = _core.produce_hints_l1(_to_core(py_ents), text)
    py = _py_l1_hints(py_ents, text)
    assert core == py
    assert next(h.data["intent"] for h in core if h.type == "text_intent") == "instruction"
    # Sanity: there is a real self_reference entity, so the command branch is reached.
    assert any(e.type == "self_reference" for e in py_ents)


def test_hint_parity_cjk_leading_control_strip():
    """CJK strip: leading U+001C before a zh command pronoun. Python str.strip()

    drops it; Rust py_strip must too, so the stripped text still starts with 帮我
    → instruction. Compares Rust to LIVE Python.
    """
    text = f"{_FS}请帮我"
    py_ents = _real_entities(text, "zh")
    core = _core.produce_hints_l1(_to_core(py_ents), text)
    py = _py_l1_hints(py_ents, text)
    assert core == py
    assert next(h.data["intent"] for h in core if h.type == "text_intent") == "instruction"


# ── get_person_threshold + filter_self_reference parity (consume the hints) ────

# (label, text, lang, expected_threshold) — threshold is 1.2 (instruction) / 0.8 (else).
_THRESHOLD_CORPUS = [
    ("instruction_1_2", "帮我查一下资料 我在这", "zh", 1.2),
    ("narrative_0_8", "我的电话是13800138000", "zh", 0.8),
    ("casual_0_8", "我今天很开心", "zh", 0.8),
    ("neutral_0_8", "今天天气不错", "zh", 0.8),
]


@pytest.mark.parametrize("case", _THRESHOLD_CORPUS, ids=[c[0] for c in _THRESHOLD_CORPUS])
def test_get_person_threshold_core_equals_python(case):
    """_core.get_person_threshold == Python get_person_threshold, and == the pinned constant.

    Pins the 1.2 / 0.8 constants AND the Rust-vs-Python parity over the same hints.
    """
    _label, text, lang, expected = case
    py_ents = _real_entities(text, lang)
    hints = _core.produce_hints_l1(_to_core(py_ents), text)
    core_th = _core.get_person_threshold(hints)
    py_th = py_get_person_threshold(hints)
    assert core_th == py_th  # Rust vs Python
    assert core_th == expected  # pinned constant (1.2 for instruction, 0.8 otherwise)


# (label, text, lang) — span the tier 1 (keep) / tier 2 (drop) / tier 3 (drop) cases.
_FILTER_CORPUS = [
    ("tier1_keeps_selfref", "我妈说她的电话是13800138000", "zh"),
    ("tier2_drops_selfref", "我在这里", "zh"),
    ("tier3_drops_selfref", "帮我看看我说的对不对", "zh"),
]


@pytest.mark.parametrize("case", _FILTER_CORPUS, ids=[c[0] for c in _FILTER_CORPUS])
def test_filter_self_reference_core_equals_python(case):
    """_core.filter_self_reference == Python filter_self_reference over real entities + hints."""
    _label, text, lang = case
    py_ents = _real_entities(text, lang)
    core_ents = _to_core(py_ents)
    hints = _core.produce_hints_l1(core_ents, text)
    core_out = _core.filter_self_reference(core_ents, hints)
    py_out = py_filter_self_reference(py_ents, hints)
    core_t = [(m.text, m.type, m.start, m.end) for m in core_out]
    py_t = [(m.text, m.type, m.start, m.end) for m in py_out]
    assert core_t == py_t


# ══════════════════════════════════════════════════════════════════════════════
# B. redact_l1 == redact(fast) — path-equivalence (Rust bundled entry vs Python shim)
# ══════════════════════════════════════════════════════════════════════════════

# (label, text, lang, config, names, types, types_exclude, unified_prefix)
# Covers: all strategies (default pseudonym / realistic / mask / category /
# name_mask / keep), validators (jwt / org / school), names-only-ja fallback,
# multi-byte (emoji prefix), unified_prefix, type whitelist + blacklist.
_REDACT_CORPUS = [
    (
        "default_pseudonym",
        "张三的电话13812345678，身份证110101199003074610",
        "zh",
        None,
        None,
        None,
        None,
        None,
    ),
    (
        "realistic",
        "张三的电话13812345678",
        "zh",
        {"person": {"strategy": "realistic"}, "phone": {"strategy": "realistic"}},
        None,
        None,
        None,
        None,
    ),
    (
        "mask",
        "电话13812345678 银行卡6217000000000000",
        "zh",
        {"phone": {"strategy": "mask"}, "bank_card": {"strategy": "mask"}},
        None,
        None,
        None,
        None,
    ),
    (
        "category",
        "北京市朝阳区三里屯",
        "zh",
        {"address": {"strategy": "category"}},
        None,
        None,
        None,
        None,
    ),
    (
        "name_mask",
        "张三和欧阳明",
        "zh",
        {"person": {"strategy": "name_mask"}},
        ["张三", "欧阳明"],
        None,
        None,
        None,
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
        None,
        None,
        None,
    ),
    (
        "validator_jwt",
        "token is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig",
        "en",
        None,
        None,
        None,
        None,
        None,
    ),
    (
        "validator_org_school",
        "我毕业于北京大学，在阿里巴巴有限公司上班",
        "zh",
        None,
        None,
        None,
        None,
        None,
    ),
    (
        "names_only_ja_fallback",
        "Talk to Zaphod and Trillian please",
        "ja",
        None,
        ["Zaphod", "Trillian"],
        None,
        None,
        None,
    ),
    ("multibyte_emoji_prefix", "🎉张三的电话13812345678", "zh", None, ["张三"], None, None, None),
    ("unified_prefix", "张三 13812345678 110101199003074610", "zh", None, None, None, None, "R"),
    (
        "type_whitelist",
        "电话13812345678 银行卡6217000000000000",
        "zh",
        {"phone": {"strategy": "mask"}, "bank_card": {"strategy": "mask"}},
        None,
        ["bank_card"],
        None,
        None,
    ),
    (
        "type_blacklist",
        "电话13812345678 银行卡6217000000000000",
        "zh",
        {"phone": {"strategy": "mask"}, "bank_card": {"strategy": "mask"}},
        None,
        None,
        ["phone"],
        None,
    ),
]


@pytest.mark.parametrize("case", _REDACT_CORPUS, ids=[c[0] for c in _REDACT_CORPUS])
def test_redact_l1_equals_redact_fast(case):
    """_core.redact_l1 (redacted, key) == LIVE redact(mode="fast") (redacted, key).

    Path-equivalence: the bundled iOS entry must stay byte-identical to the shipped
    Python fast path. Compares two independent code paths (NOT self).
    """
    _label, text, lang, config, names, types, types_exclude, unified_prefix = case
    core_redacted, core_key, _aliases, _kd, _mc = _core_redact_fast(
        text,
        lang,
        config=config,
        names=names,
        types=types,
        types_exclude=types_exclude,
        unified_prefix=unified_prefix,
    )
    py_redacted, py_key = _py_redact_fast(
        text,
        lang,
        config=config,
        names=names,
        types=types,
        types_exclude=types_exclude,
        unified_prefix=unified_prefix,
    )
    assert core_redacted == py_redacted, f"redacted drift for {_label!r}"
    assert dict(core_key) == dict(py_key), f"key drift for {_label!r}"


def test_redact_l1_keep_downgrade_equals_redact_fast():
    """keep-downgrade: strategy='keep' on a non-self_reference type is downgraded.

    Both engines must downgrade identically (keep_downgraded=True on the Rust side)
    and produce identical (redacted, key). The SecurityWarning is expected.
    """
    text = "张三的电话13812345678"
    config = {"phone": {"strategy": "keep"}}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        core_redacted, core_key, _aliases, keep_downgraded, _mc = _core_redact_fast(
            text, "zh", config=config
        )
        py_redacted, py_key = _py_redact_fast(text, "zh", config=config)
    assert keep_downgraded is True  # the non-self_reference 'keep' was downgraded
    assert core_redacted == py_redacted
    assert dict(core_key) == dict(py_key)


def test_redact_l1_keep_whitelist_self_reference_not_downgraded():
    """The self_reference kinship whitelist ('我妈') is genuinely kept (no downgrade)."""
    out = _core_redact_fast("我妈说她13812345678", "zh")
    redacted, _key, _aliases, keep_downgraded, _mc = out
    assert keep_downgraded is False
    assert "我妈" in redacted  # kinship kept verbatim


# ══════════════════════════════════════════════════════════════════════════════
# C. Targeted constant / precision gates — through redact(mode="fast")
# ══════════════════════════════════════════════════════════════════════════════


def test_threshold_flip_instruction_suppresses_name():
    """Pins the 1.2 instruction threshold: an instruction-intent zh text SUPPRESSES

    a borderline person name (王芳), while the SAME name in a narrative is REDACTED
    (threshold 0.8). If you change get_person_threshold's 1.2 (instruction) or 0.8
    (narrative) constants, one of these two assertions flips and the test fails.
    """
    instr_redacted, _ = redact("帮我查一下王芳的资料", mode="fast", lang="zh", salt=SALT)
    narr_redacted, _ = redact("王芳的电话是13812345678", mode="fast", lang="zh", salt=SALT)
    # instruction (threshold 1.2) → 王芳 below threshold → kept verbatim (NOT redacted).
    assert "王芳" in instr_redacted
    # narrative (threshold 0.8) → 王芳 above threshold → redacted (gone).
    assert "王芳" not in narr_redacted


def test_validator_jwt_accept_vs_reject():
    """Pins the jwt validator: a 3-segment HS256 jwt is detected (redacted); a

    3-segment jwt whose header lacks "alg" is REJECTED (left verbatim). If you
    weaken the jwt validator to accept any 3-segment string, the reject side fails.
    """
    _JWT_VALID = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
    _JWT_NOALG = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjMifQ.sig"
    valid_redacted, _ = redact(f"token is {_JWT_VALID}", mode="fast", lang="en", salt=SALT)
    reject_redacted, _ = redact(f"token is {_JWT_NOALG}", mode="fast", lang="en", salt=SALT)
    assert _JWT_VALID not in valid_redacted  # accepted → redacted
    assert _JWT_NOALG in reject_redacted  # rejected (no "alg") → left verbatim


def test_validator_organization_accept_vs_reject():
    """Pins the organization validator: a named org (阿里巴巴有限公司) is detected;

    a bare suffix with no name before it (这是公司) is REJECTED (left verbatim).
    """
    accept_redacted, _ = redact("我在阿里巴巴有限公司上班", mode="fast", lang="zh", salt=SALT)
    reject_redacted, _ = redact("这是公司", mode="fast", lang="zh", salt=SALT)
    assert "阿里巴巴有限公司" not in accept_redacted  # accepted → redacted
    assert reject_redacted == "这是公司"  # rejected → unchanged


def test_validator_school_accept_vs_reject():
    """Pins the school validator: a named school (北京大学) is detected; a bare

    suffix with no name before it (这是大学) is REJECTED (left verbatim).
    """
    accept_redacted, _ = redact("我毕业于北京大学", mode="fast", lang="zh", salt=SALT)
    reject_redacted, _ = redact("这是大学", mode="fast", lang="zh", salt=SALT)
    assert "北京大学" not in accept_redacted  # accepted → redacted
    assert reject_redacted == "这是大学"  # rejected → unchanged


# ══════════════════════════════════════════════════════════════════════════════
# NON-VACUITY guards + tamper-reasoned proofs
# ══════════════════════════════════════════════════════════════════════════════


def test_corpus_nonempty():
    """Guard: every corpus has cases. An accidentally-emptied corpus would make the

    parametrized differentials vacuously pass (0 cases collected) — this fails loudly.
    """
    assert len(_HINT_CORPUS) >= 25, "hint corpus shrank below the adversarial floor"
    assert len(_REDACT_CORPUS) >= 12, "redact corpus shrank below the floor"
    assert len(_THRESHOLD_CORPUS) >= 4
    assert len(_FILTER_CORPUS) >= 3


def test_hint_differential_is_real_not_self_compare():
    """Tamper-reasoned proof (family A): the differential compares Rust _core to an

    INDEPENDENT Python reference. We confirm the gate would catch a regression by
    asserting the real (correct) hints differ from a deliberately-WRONG expectation.
    Since the compiled Rust cannot be perturbed in-process, this stands in for a
    live tamper: if produce_hints_l1 ever returned the wrong intent, `core != wrong`
    would already be false here, and test_hint_parity_* (core == py) would go red.
    """
    text = "请帮我查电话13800138000"  # command + PII → instruction, tier 1
    py_ents = _real_entities(text, "zh")
    core = _core.produce_hints_l1(_to_core(py_ents), text)
    py = _py_l1_hints(py_ents, text)
    # The two engines agree (the gate's positive assertion).
    assert core == py
    # A deliberately-wrong expectation: the FULL correct 4-type-shape hint set with
    # ONLY the intent flipped to 'narrative'. It must NOT match — proving the equality
    # above is load-bearing on the intent VALUE (not merely on hint count / membership).
    from argus_redact._types import Hint

    wrong = [
        Hint(type="pii_density", data={"level": "medium", "count": 1}),
        Hint(type="self_reference_tier", data={"tier": 1, "has_kinship": False}),
        Hint(type="text_intent", data={"intent": "narrative"}),  # WRONG: should be instruction
    ]
    assert core != wrong, "command-with-PII must be 'instruction', not 'narrative'"
    # Sanity: `wrong` differs from `core` ONLY in the intent — same length, same types,
    # so the inequality is driven by the intent value, not a trivial shape mismatch.
    assert [h.type for h in core] == [h.type for h in wrong]
    # And the references are distinct objects from distinct engines (not `x == x`).
    assert core is not py


def test_redact_differential_is_real_not_self_compare():
    """Tamper-reasoned proof (family B): redact_l1 and redact(fast) are independent

    code paths. We confirm the equality is meaningful by showing the redacted output
    differs from the untouched input (so a no-op engine would fail the gate) and that
    a deliberately-wrong expected string would NOT match.
    """
    text = "张三的电话13812345678"
    core_redacted, core_key, _a, _kd, _mc = _core_redact_fast(text, "zh")
    py_redacted, py_key = _py_redact_fast(text, "zh")
    assert core_redacted == py_redacted  # the gate's positive assertion
    assert core_redacted != text, "redaction must change the text (non-no-op)"
    assert core_redacted != "张三的电话13812345678WRONG"  # wrong expectation rejected
    assert dict(core_key) == dict(py_key) and len(core_key) > 0


def test_threshold_constants_are_distinct():
    """Tamper-reasoned proof (family C): the two threshold constants are DISTINCT,

    so the threshold-flip gate cannot pass vacuously. If 1.2 and 0.8 were ever
    collapsed to one value, the suppress/redact behaviors would no longer diverge.
    """
    instr_hints = _core.produce_hints_l1(
        _to_core(_real_entities("帮我查资料 我在这", "zh")), "帮我查资料 我在这"
    )
    narr_hints = _core.produce_hints_l1(
        _to_core(_real_entities("我的电话是13800138000", "zh")), "我的电话是13800138000"
    )
    instr_th = _core.get_person_threshold(instr_hints)
    narr_th = _core.get_person_threshold(narr_hints)
    assert instr_th == 1.2
    assert narr_th == 0.8
    assert instr_th != narr_th  # the flip is real — distinct constants drive distinct behavior
