"""`_core.detect_l1` / `redact_l1` / `produce_hints_l1` / `get_person_threshold` /
`filter_self_reference` bindings (Task 7 of v0.7.7).

These PyO3 functions expose the Rust L1 engine. Until T8 routes the Python
fast-mode pipeline through `_core`, the pure-Python pipeline is the reference:
every expectation is captured by running the SAME input through Python and the
binding output must match it field-for-field (confidence compared with exact
`==`, no rounding; hints compared with the frozen-dataclass `__eq__`).

The hint bindings must interop with `argus_redact._types.Hint`: `produce_hints_l1`
returns real `_types.Hint` instances so it is `==`-comparable to the L1 slice of
Python `produce_hints`, and the consumers (`get_person_threshold` /
`filter_self_reference`) read those instances duck-typed (`.type` / `.data`).
"""

import json
from pathlib import Path

import pytest

import argus_redact._core as _core
from argus_redact import redact
from argus_redact._types import PatternMatch as PyPM
from argus_redact.glue.redact import _detect
from argus_redact.pure.hints import (
    filter_self_reference as py_filter_self_reference,
    get_person_threshold as py_get_person_threshold,
    produce_hints as py_produce_hints,
)
from argus_redact.pure.replacer import (
    DEFAULT_PREFIXES,
    _KEEP_WHITELIST,
    _build_type_info,
)

FIXTURE_REDACT = Path(__file__).parent / "fixtures" / "redact_l1_v077.json"
SALT = 42  # matches the T1 fixture freeze.

_L1_HINT_TYPES = ("text_intent", "self_reference_tier")


def _tuples(matches):
    """(text, type, start, end, confidence, layer) per match, order-preserving."""
    return [(m.text, m.type, m.start, m.end, m.confidence, m.layer) for m in matches]


def _pm(text, type_, start, end, confidence=1.0, layer=1):
    return _core.PatternMatch(text, type_, start, end, confidence, layer)


def _py_l1_hints(entities, text, near_misses=None):
    """The L1 slice of Python `produce_hints` (text_intent + self_reference_tier)."""
    hints = py_produce_hints(entities, text, near_misses=near_misses)
    return [h for h in hints if h.type in _L1_HINT_TYPES]


# ══════════════════════════════════════════════════════════════════════════════
# produce_hints_l1 — real _types.Hint instances, == Python produce_hints (L1)
# ══════════════════════════════════════════════════════════════════════════════


def test_produce_hints_l1_returns_types_hint_instances():
    from argus_redact._types import Hint

    ents = [_pm("me", "self_reference", 0, 2), _pm("555-1234", "phone", 18, 26)]
    text = "me and the number 555-1234 are here"
    out = _core.produce_hints_l1(ents, text)
    assert isinstance(out, list)
    assert all(isinstance(h, Hint) for h in out)


def test_produce_hints_l1_self_reference_plus_pii_equals_python():
    # Self-reference + other PII → self_reference_tier(1) + text_intent(narrative).
    ents = [_pm("me", "self_reference", 0, 2), _pm("555-1234", "phone", 18, 26)]
    text = "me and the number 555-1234 are here"
    core = _core.produce_hints_l1(ents, text)
    py = _py_l1_hints(
        [PyPM("me", "self_reference", 0, 2, 1.0, 1), PyPM("555-1234", "phone", 18, 26, 1.0, 1)],
        text,
    )
    assert core == py
    # Confirm the exact data value types Python uses (int tier, bool kinship, str intent).
    by_type = {h.type: h.data for h in core}
    assert by_type["self_reference_tier"] == {"tier": 1, "has_kinship": False}
    assert isinstance(by_type["self_reference_tier"]["tier"], int)
    assert isinstance(by_type["self_reference_tier"]["has_kinship"], bool)
    assert by_type["text_intent"] == {"intent": "narrative"}
    assert isinstance(by_type["text_intent"]["intent"], str)


@pytest.mark.parametrize(
    "ents, text",
    [
        # neutral: no self-ref, no PII → only text_intent.
        ([], "hello world"),
        # narrative: no self-ref, PII present.
        ([("555-1234", "phone", 5, 13)], "call 555-1234"),
        # instruction tier 3: self-ref + command, no kinship, no other PII.
        ([("me", "self_reference", 12, 14)], "please tell me about it"),
        # casual tier 2: pure pronoun self-ref, no PII, no command.
        ([("me", "self_reference", 5, 7)], "just me here"),
        # casual tier 1 kinship (zh): 我妈 is kinship, not a command.
        ([("我妈", "self_reference", 0, 2)], "我妈在这里"),
        # instruction tier 1: command + kinship.
        ([("我妈", "self_reference", 3, 5)], "请帮我找我妈"),
    ],
)
def test_produce_hints_l1_decision_tree_equals_python(ents, text):
    core_ents = [_pm(*e) for e in ents]
    py_ents = [PyPM(e[0], e[1], e[2], e[3], 1.0, 1) for e in ents]
    assert _core.produce_hints_l1(core_ents, text) == _py_l1_hints(py_ents, text)


# ══════════════════════════════════════════════════════════════════════════════
# get_person_threshold — 1.2 / 0.8, == Python (consuming _types.Hint instances)
# ══════════════════════════════════════════════════════════════════════════════


def test_get_person_threshold_instruction_is_1_2():
    hints = _core.produce_hints_l1([_pm("me", "self_reference", 12, 14)], "please tell me about it")
    assert _core.get_person_threshold(hints) == 1.2
    assert _core.get_person_threshold(hints) == py_get_person_threshold(hints)


def test_get_person_threshold_narrative_is_0_8():
    ents = [_pm("me", "self_reference", 0, 2), _pm("555", "phone", 11, 14)]
    hints = _core.produce_hints_l1(ents, "me and the 555 number")
    assert _core.get_person_threshold(hints) == 0.8
    assert _core.get_person_threshold(hints) == py_get_person_threshold(hints)


def test_get_person_threshold_neutral_and_empty_default_0_8():
    neutral = _core.produce_hints_l1([], "hello world")
    assert _core.get_person_threshold(neutral) == 0.8
    assert _core.get_person_threshold([]) == 0.8
    assert _core.get_person_threshold([]) == py_get_person_threshold([])


# ══════════════════════════════════════════════════════════════════════════════
# filter_self_reference — tier 1 keeps, else drops; == Python
# ══════════════════════════════════════════════════════════════════════════════


def _fents_core():
    return [_pm("me", "self_reference", 0, 2), _pm("555", "phone", 11, 14)]


def _fents_py():
    return [PyPM("me", "self_reference", 0, 2, 1.0, 1), PyPM("555", "phone", 11, 14, 1.0, 1)]


def test_filter_self_reference_tier1_keeps_all():
    # tier 1 (self-ref + other PII) keeps the self_reference.
    hints = _core.produce_hints_l1(_fents_core(), "me and the 555 number")
    core = _core.filter_self_reference(_fents_core(), hints)
    py = py_filter_self_reference(_fents_py(), hints)
    assert _tuples(core) == [("me", "self_reference", 0, 2, 1.0, 1), ("555", "phone", 11, 14, 1.0, 1)]
    assert _tuples(core) == _tuples(py)


def test_filter_self_reference_tier2_drops_self_reference():
    # tier 2 (pure pronoun, no PII, no command) drops the self_reference.
    hints = _core.produce_hints_l1([_pm("me", "self_reference", 5, 7)], "just me here")
    core = _core.filter_self_reference(_fents_core(), hints)
    py = py_filter_self_reference(_fents_py(), hints)
    assert _tuples(core) == [("555", "phone", 11, 14, 1.0, 1)]
    assert _tuples(core) == _tuples(py)


def test_filter_self_reference_no_tier_hint_drops_self_reference():
    core = _core.filter_self_reference(_fents_core(), [])
    py = py_filter_self_reference(_fents_py(), [])
    assert _tuples(core) == [("555", "phone", 11, 14, 1.0, 1)]
    assert _tuples(core) == _tuples(py)


# ══════════════════════════════════════════════════════════════════════════════
# detect_l1 — (layer1, person, hints, near_misses); layer1+person == Python
#             pre-merge entities (RAW, unmerged — the four components serve T8).
# ══════════════════════════════════════════════════════════════════════════════


def _py_pre_merge_detect(text, langs, names=None):
    """Replicate the L1 portion of `_detect` up to (but NOT including) the merge.

    `detect_l1` returns the RAW (pre-merge) entity components, so the Python
    reference is the `entities` list right before `merge_entities` — built from
    `match_patterns` (with offset map-back) + zh/en person + names-only fallback,
    in the same `entities.extend(...)` order. Returns `(entities, near_misses)`.
    """
    import re

    from argus_redact.glue.redact import _load_patterns, _tag_layer
    from argus_redact.layers import LAYER_REGEX
    from argus_redact.pure.hints import get_person_threshold
    from argus_redact.pure.normalize import map_spans_to_original, normalize_text
    from argus_redact.pure.patterns import match_patterns

    if isinstance(langs, str):
        langs = [langs]
    entities = []
    normalized, offset_map = normalize_text(text)
    use_normalized = offset_map is not None
    detect_text = normalized if use_normalized else text
    layer1_raw, near_misses = match_patterns(detect_text, _load_patterns(langs))
    if use_normalized and layer1_raw:
        mapped = map_spans_to_original(
            [(e.start, e.end) for e in layer1_raw], offset_map, len(text)
        )
        layer1 = [
            PyPM(text[s:e], eo.type, s, e, eo.confidence, eo.layer)
            for eo, (s, e) in zip(layer1_raw, mapped)
        ]
    else:
        layer1 = layer1_raw
    entities.extend(_tag_layer(layer1, LAYER_REGEX))
    hints = py_produce_hints(layer1, text, near_misses=near_misses)
    threshold = get_person_threshold(hints)
    if "zh" in langs:
        from argus_redact.lang.zh.person import detect_person_names

        pn = detect_person_names(text, pii_entities=layer1, known_names=names, threshold=threshold)
        entities.extend(_tag_layer(pn, LAYER_REGEX))
    if "en" in langs:
        from argus_redact.lang.en.person import detect_person_names as den

        entities.extend(_tag_layer(den(text, known_names=names), LAYER_REGEX))
    if "zh" not in langs and "en" not in langs and names:
        for name in names:
            if not name:
                continue
            for m in re.finditer(re.escape(name), text):
                entities.append(
                    PyPM(name, "person", m.start(), m.end(), 1.0, LAYER_REGEX)
                )
    return entities, near_misses


@pytest.mark.parametrize(
    "text, lang, names",
    [
        # zh: normalize + near-miss path (id/credit_code fail validation).
        ("我叫张伟，电话13800138000，身份证110101199003078888。", ["zh"], None),
        # en: two surname-list names.
        ("Contact John Smith or Mary Johnson at the office.", ["en"], None),
        # names-only fallback (ja → neither zh nor en).
        ("Talk to Zaphod and Trillian please", ["ja"], ["Zaphod", "Trillian"]),
        # combined zh + en (person order: zh then en).
        ("张三 and John Smith met, phone 13800138000", ["zh", "en"], None),
    ],
)
def test_detect_l1_components_equal_python_pre_merge(text, lang, names):
    layer1, person, hints, near_misses = _core.detect_l1(text, lang, names)
    assert all(isinstance(m, _core.PatternMatch) for m in layer1 + person + near_misses)
    py_entities, py_near = _py_pre_merge_detect(text, lang, names)
    # layer1 ++ person == Python pre-merge entities (RAW order).
    assert _tuples(layer1 + person) == _tuples(py_entities)
    # near_misses match (text/type/span — confidence is the fixed 0.3 near-miss).
    assert [(m.text, m.type, m.start, m.end) for m in near_misses] == [
        (m.text, m.type, m.start, m.end) for m in py_near
    ]
    # hints == the L1 slice of Python produce_hints over layer1 (the L1a set).
    py_l1 = layer1  # already pre-merge layer1; person not part of hint input
    # Reconstruct Python hints from the same layer1 the core used.
    py_hints = _py_l1_hints(
        [PyPM(m.text, m.type, m.start, m.end, m.confidence, m.layer) for m in py_l1],
        text,
        near_misses=py_near,
    )
    assert hints == py_hints


def test_detect_l1_default_names_is_empty():
    # Omitting known_names behaves like the empty-names default.
    a = _core.detect_l1("Contact John Smith today", ["en"])
    b = _core.detect_l1("Contact John Smith today", ["en"], None)
    assert _tuples(a[0] + a[1]) == _tuples(b[0] + b[1])


# ══════════════════════════════════════════════════════════════════════════════
# redact_l1 — (redacted, key, aliases, keep_downgraded); == T1 fixture + Python
# ══════════════════════════════════════════════════════════════════════════════


def _core_redact_fast(text, lang, *, config=None, names=None, types=None, types_exclude=None, unified_prefix=None):
    """Drive `_core.redact_l1` the way the Python fast-mode pipeline does.

    Builds `type_info` / `custom_fakers` via the SAME `_build_type_info` the
    Python `replace()` uses, resolves the prefixes / keep_whitelist identically,
    and forwards the detect_l1 `lang` / `names` + the type filter. The pre-replace
    entity capture (for `_build_type_info`'s type set) comes from `_detect`, which
    is what T8 will ultimately route through `_core.redact_l1` directly.
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


# (label, text, lang, config, names, unified_prefix) — a subset of the T1 corpus
# covering: pseudonym MT-stream (zh_default), realistic built-in faker (zh/en),
# mask, keep (kinship whitelist), category, name_mask, and unified_prefix.
_FIXTURE_CASES = [
    ("zh_default", "张三的电话13812345678，身份证110101199003074610", "zh", None, None, None),
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
        None,
    ),
    (
        "zh_mask",
        "电话13812345678 银行卡6217000000000000",
        "zh",
        {"phone": {"strategy": "mask"}, "bank_card": {"strategy": "mask"}},
        None,
        None,
    ),
    ("zh_keep", "我妈说她13812345678", "zh", None, None, None),
    ("zh_category", "北京市朝阳区三里屯", "zh", {"address": {"strategy": "category"}}, None, None),
    ("zh_name_mask", "张三和欧阳明", "zh", {"person": {"strategy": "name_mask"}}, ["张三", "欧阳明"], None),
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
    ),
    ("unified_prefix", "张三 13812345678 110101199003074610", "zh", None, None, "R"),
]


@pytest.mark.parametrize("case", _FIXTURE_CASES, ids=[c[0] for c in _FIXTURE_CASES])
def test_redact_l1_matches_t1_fixture(case):
    """`_core.redact_l1` == the frozen T1 (redacted, key) at SALT=42."""
    label, text, lang, config, names, unified_prefix = case
    golden = json.loads(FIXTURE_REDACT.read_text(encoding="utf-8"))[label]
    redacted, key, _aliases, _kd = _core_redact_fast(
        text, lang, config=config, names=names, unified_prefix=unified_prefix
    )
    assert redacted == golden["redacted"], f"redacted drift for {label!r}"
    assert dict(sorted(key.items())) == golden["key"], f"key drift for {label!r}"


@pytest.mark.parametrize("case", _FIXTURE_CASES, ids=[c[0] for c in _FIXTURE_CASES])
def test_redact_l1_matches_python_redact_fast(case):
    """`_core.redact_l1` (redacted, key) == live Python `redact(mode='fast')`."""
    _label, text, lang, config, names, unified_prefix = case
    redacted, key, _aliases, _kd = _core_redact_fast(
        text, lang, config=config, names=names, unified_prefix=unified_prefix
    )
    kw = dict(mode="fast", lang=lang, salt=SALT, config=config)
    if names is not None:
        kw["names"] = names
    if unified_prefix is not None:
        kw["unified_prefix"] = unified_prefix
    py_redacted, py_key = redact(text, **kw)
    assert redacted == py_redacted
    assert dict(key) == dict(py_key)


def test_redact_l1_keep_downgraded_surfaces():
    """The 4-tuple's `keep_downgraded` flag is surfaced (False on a clean run)."""
    out = _core_redact_fast("张三的电话13812345678，身份证110101199003074610", "zh")
    assert len(out) == 4
    redacted, key, aliases, keep_downgraded = out
    assert isinstance(keep_downgraded, bool)
    assert keep_downgraded is False
    assert isinstance(aliases, dict)


def test_redact_l1_type_filter_keeps_only_listed():
    """`types` keeps only listed types (phone dropped, bank_card masked)."""
    redacted, key, _aliases, _kd = _core_redact_fast(
        "电话13812345678 银行卡6217000000000000",
        "zh",
        config={"phone": {"strategy": "mask"}, "bank_card": {"strategy": "mask"}},
        types=["bank_card"],
    )
    assert "13812345678" in redacted  # phone left intact (filtered out)
    assert "13812345678" not in key.values()
    assert "6217000000000000" in key.values()  # bank_card masked


def test_redact_l1_type_filter_exclude_listed():
    """`types_exclude` drops the listed type (phone left intact)."""
    redacted, _key, _aliases, _kd = _core_redact_fast(
        "电话13812345678 银行卡6217000000000000",
        "zh",
        config={"phone": {"strategy": "mask"}, "bank_card": {"strategy": "mask"}},
        types_exclude=["phone"],
    )
    assert "13812345678" in redacted
    assert "621700******0000" in redacted


# ══════════════════════════════════════════════════════════════════════════════
# pathological input — must not panic (graceful find_iter on backtrack/overflow)
# ══════════════════════════════════════════════════════════════════════════════


def test_redact_pathological_single_token_does_not_raise():
    """A ~1MB single token (within the 1MB cap) tripped fancy_regex's backtrack /
    stack-overflow limit, which used to escape as a PanicException from `redact`.
    The graceful `find_iter` now stops scanning rather than panicking, so the
    public API must return cleanly (no PanicException, no other raise)."""
    pathological = "A" + "a" * 1_000_000  # 1,000,001 chars, under the 1MB cap
    # Just must not raise — the result is whatever the graceful scan yields.
    redacted, _key = redact(pathological, lang="en", mode="fast")
    assert isinstance(redacted, str)
