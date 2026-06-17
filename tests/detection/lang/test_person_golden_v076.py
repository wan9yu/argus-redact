"""Frozen golden for pure-Python person detection (zh + en) — pre-port safety net.

This is the safety net for the v0.7.6 person-detection port. It freezes the
EXACT output of the current pure-Python ``detect_person_names`` (Chinese and
English) over a corpus that pins every scoring path: float thresholds, 2-char vs
3-char variant ties, swallow detection, PII-proximity buckets (50 / 150),
the ±20 context window, compound-vs-single surname overlap, particle trimming,
the full single-surname pool, multi-byte (emoji) offsets, and the English
surname/given-name confidence rules.

The fixtures under ``tests/core/fixtures/`` are captured from the live functions
(never hand-written) and committed. The parametrized test below replays the
current functions and asserts byte-for-byte equality with the frozen output,
INCLUDING exact float equality on confidence (``==``, never ``approx``). Later
tasks that repoint ``detect_person_names`` at a Rust-backed shim must keep this
test green unchanged.

To regenerate the fixtures (only when the underlying behavior changes on
purpose), run this file directly::

    python tests/detection/lang/test_person_golden_v076.py

It rewrites both JSON files from the live functions; review the diff before
committing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus_redact._types import PatternMatch
from argus_redact.lang.en.person import detect_person_names as detect_en
from argus_redact.lang.zh.person import detect_person_names as detect_zh

_FIXTURE_DIR = Path(__file__).resolve().parents[2] / "core" / "fixtures"
_ZH_FIXTURE = _FIXTURE_DIR / "zh_person_detection_v076.json"
_EN_FIXTURE = _FIXTURE_DIR / "en_person_detection_v076.json"


# ── PatternMatch <-> dict round-trip ──
#
# pii_entities must survive JSON serialization. score_candidate only reads
# ``.start``, ``.end`` (proximity distance) and detect_person_names filters on
# ``.type`` (drops "self_reference"); we capture text/type/start/end/confidence
# for a faithful reconstruction. Stored as plain dicts, never Python reprs.


def _pm_to_dict(pm: PatternMatch) -> dict:
    return {
        "text": pm.text,
        "type": pm.type,
        "start": pm.start,
        "end": pm.end,
        "confidence": pm.confidence,
    }


def _dict_to_pm(d: dict) -> PatternMatch:
    return PatternMatch(
        text=d["text"],
        type=d["type"],
        start=d["start"],
        end=d["end"],
        confidence=d.get("confidence", 1.0),
    )


# ── Corpus construction ──
#
# Each entry is a dict the capture routine reads to drive the live function and
# the replay test reads to assert. Shape:
#   {id, lang, input, pii_entities, known_names, threshold}
# The capture step fills in "output" by running the live function.


def _existing_zh_fixture_cases() -> list[dict]:
    """The 24 cases from tests/fixtures/zh_person.json, replayed with no PII."""
    src = Path(__file__).resolve().parents[2] / "fixtures" / "zh_person.json"
    raw = json.loads(src.read_text(encoding="utf-8"))
    cases = []
    for c in raw:
        cases.append(
            {
                "id": "zh_corpus_" + c["id"],
                "lang": "zh",
                "input": c["input"],
                "pii_entities": [],
                "known_names": None,
                "threshold": 0.8,
            }
        )
    return cases


def _zh_edge_cases() -> list[dict]:
    cases: list[dict] = []

    def add(case_id, text, *, pii=None, known=None, threshold=0.8):
        cases.append(
            {
                "id": case_id,
                "lang": "zh",
                "input": text,
                "pii_entities": [_pm_to_dict(p) for p in (pii or [])],
                "known_names": known,
                "threshold": threshold,
            }
        )

    # ── float boundary: scores landing exactly on / just below 0.8 ──
    # 2-char base 0.3. Strong proximity (d<=50) → +0.5 = 0.8 (passes, == threshold).
    # Weak proximity (50<d<=150) → +0.3 = 0.6 (fails). One signal flips the result.
    far_text = "张明" + ("，" * 200) + "13812345678"
    add(
        "zh_float_2char_strong_at_threshold",
        far_text,
        pii=[PatternMatch("13812345678", "phone", 52, 63)],  # distance 50 → 0.8
    )
    add(
        "zh_float_2char_weak_below_threshold",
        far_text,
        pii=[PatternMatch("13812345678", "phone", 122, 133)],  # distance 120 → 0.6
    )
    # 3-char base 0.4. Weak proximity → 0.7 (fails); a 3-char that *just* misses.
    far_text3 = "何秀珍" + ("，" * 200) + "13812345678"
    add(
        "zh_float_3char_weak_below_threshold",
        far_text3,
        pii=[PatternMatch("13812345678", "phone", 123, 134)],  # distance 120 → 0.7
    )

    # ── 2-char-vs-3-char variant tie: a 3-char candidate that emits both ──
    # 何秀珍 generates 何秀珍 (3) and 何秀 (2). With a context prefix both pass;
    # resolution prefers the 3-char.
    add("zh_variant_tie_prefer_3char", "客户何秀珍已登记")

    # ── swallow detection: 3rd char begins a common_words.txt entry ──
    # 张三预 → 预 starts 预订 (common word) → resolution prefers 2-char 张三.
    add(
        "zh_swallow_prefer_2char",
        "张三预订了机票",
        pii=[PatternMatch("13800000000", "phone", 0, 0)],
    )

    # ── PII proximity boundaries: distance 49 / 50 / 51 and 149 / 150 / 151 ──
    # distance = pii.start - candidate.end ; candidate 张明 ends at 2 → pii.start = d + 2.
    prox_text = "张明" + ("，" * 250) + "13812345678"
    for d in (49, 50, 51, 149, 150, 151):
        add(
            f"zh_proximity_distance_{d}",
            prox_text,
            pii=[PatternMatch("13812345678", "phone", d + 2, d + 13)],
        )

    # ── context window ±19/20/21: prefix word vs name at depth 19/20/21 ──
    # Filler between '客户' and the name breaks the anchored prefix regex; these
    # lock that name-start position around the 20-char window does not revive it.
    for target in (19, 20, 21):
        pad = target - 2  # '客户' is 2 chars; name starts at 2 + pad = target
        add(f"zh_window_namestart_{target}", "客户" + ("啊" * pad) + "张明")
    # Adjacent prefix (within window) — the positive control: prefix fires.
    add("zh_window_prefix_adjacent", "客户张明已登记")

    # ── compound-vs-single surname overlap (欧阳 compound vs 欧 single) ──
    add("zh_compound_vs_single", "客户欧阳明已登记")

    # ── particle trim: trailing char in the not-name set is stripped ──
    # 张明了 → '了' is a particle → trimmed to 张明 (confidence 0.8999999999999999).
    add("zh_particle_trim", "客户张明了解情况")

    # ── CJK multi-byte offset: emoji / multi-byte char before the name ──
    # Char-vs-byte offset bugs would surface here (emoji is 1 Python char).
    add("zh_emoji_offset", "😀客户张明的手机号13812345678")
    add("zh_emoji_offset_multi", "🎉🎊客户李芳，电话13912345678")

    # ── non-default threshold path ──
    # threshold 0.7 lets a 3-char weak-proximity candidate (0.7) pass.
    add(
        "zh_threshold_0_7_passes_3char",
        far_text3,
        pii=[PatternMatch("13812345678", "phone", 123, 134)],
        threshold=0.7,
    )

    # ── known_names bypass (confidence 1.0, even for a negative-dict word) ──
    add("zh_known_names_bypass", "下午和高明开会讨论方案", known=["高明"])

    # ── self_reference PII is filtered before proximity scoring ──
    # A self_reference entity next to the name must NOT grant a proximity bonus.
    add(
        "zh_self_reference_filtered",
        "张明" + ("，" * 200) + "13812345678",
        pii=[PatternMatch("我", "self_reference", 3, 4)],
    )

    return cases


def _zh_surname_sweep_cases() -> list[dict]:
    """Each single surname once in minimal positive context — locks the pool."""
    # Local import: only the regeneration (__main__) path builds the sweep
    # corpus, so the replay+assert path never needs surnames.py. Keeping it
    # lazy lets this test keep collecting if surnames.py is later removed.
    from argus_redact.lang.zh.surnames import SURNAMES

    cases = []
    for s in SURNAMES:
        cases.append(
            {
                "id": f"zh_surname_sweep_{s}",
                "lang": "zh",
                "input": f"客户{s}磊",
                "pii_entities": [],
                "known_names": None,
                "threshold": 0.8,
            }
        )
    return cases


def _en_cases() -> list[dict]:
    cases: list[dict] = []

    def add(case_id, text, *, known=None):
        cases.append(
            {
                "id": case_id,
                "lang": "en",
                "input": text,
                "pii_entities": None,  # en has no pii_entities param
                "known_names": known,
                "threshold": None,  # en has no threshold param
            }
        )

    # The six required en cases:
    add("en_known_names_exact", "O'Brien filed the report.", known=["O'Brien"])  # → 1.0
    add("en_surname_plus_known_given", "Email John Smith today.")  # → 1.0
    add("en_surname_plus_unknown_given", "Quincy Smith arrived.")  # → 0.9
    add("en_single_surname_alone", "Smith arrived.")  # → no match
    add("en_initial_form", "J. Smith joined.")  # → J. Smith, 0.9
    add("en_adjacency_gap_negative", "John, Smith arrived.")  # → no match (comma gap)

    # Folded-in coverage from tests/detection/lang/test_en_person.py:
    add("en_middle_initial", "John A. Smith joined.")
    add("en_first_middle_last", "Mary Ann Johnson called.")
    add("en_lowercase_surname_negative", "john smith called.")
    add("en_unknown_surname_negative", "John Xeoplux arrived.")
    add("en_no_capitalized_pattern", "call them later")

    return cases


def _build_zh_corpus() -> list[dict]:
    return (
        _existing_zh_fixture_cases()
        + _zh_edge_cases()
        + _zh_surname_sweep_cases()
    )


def _build_en_corpus() -> list[dict]:
    return _en_cases()


# ── Capture (regeneration) ──


def _run_zh_case(case: dict) -> list[dict]:
    pii = [_dict_to_pm(p) for p in case["pii_entities"]] if case["pii_entities"] else None
    out = detect_zh(
        case["input"],
        pii_entities=pii,
        known_names=case["known_names"],
        threshold=case["threshold"],
    )
    return [_pm_to_dict(m) for m in out]


def _run_en_case(case: dict) -> list[dict]:
    out = detect_en(case["input"], known_names=case["known_names"])
    return [_pm_to_dict(m) for m in out]


def _capture(corpus: list[dict], runner) -> list[dict]:
    frozen = []
    for case in corpus:
        entry = dict(case)
        entry["output"] = runner(case)
        frozen.append(entry)
    return frozen


def _regenerate() -> None:
    _FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    zh = _capture(_build_zh_corpus(), _run_zh_case)
    en = _capture(_build_en_corpus(), _run_en_case)
    _ZH_FIXTURE.write_text(
        json.dumps(zh, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    _EN_FIXTURE.write_text(
        json.dumps(en, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(zh)} zh cases → {_ZH_FIXTURE.name}")
    print(f"wrote {len(en)} en cases → {_EN_FIXTURE.name}")


# ── Replay test (the safety net) ──


def _load(fixture: Path) -> list[dict]:
    return json.loads(fixture.read_text(encoding="utf-8"))


_ZH_FROZEN = _load(_ZH_FIXTURE) if _ZH_FIXTURE.exists() else []
_EN_FROZEN = _load(_EN_FIXTURE) if _EN_FIXTURE.exists() else []


def test_fixtures_present():
    # Guard the soft spot: an emptied/missing fixture would make the
    # parametrize([]) tests silently skip (green). Fail loudly instead.
    assert _ZH_FIXTURE.exists() and len(_ZH_FROZEN) > 0
    assert _EN_FIXTURE.exists() and len(_EN_FROZEN) > 0


@pytest.mark.parametrize("case", _ZH_FROZEN, ids=[c["id"] for c in _ZH_FROZEN])
def test_zh_person_golden(case):
    actual = _run_zh_case(case)
    expected = case["output"]
    assert len(actual) == len(expected), f"count mismatch for {case['id']}"
    for a, e in zip(actual, expected):
        assert a["text"] == e["text"]
        assert a["type"] == e["type"]
        assert a["start"] == e["start"]
        assert a["end"] == e["end"]
        # Exact float equality — confidence must match bit-for-bit, not approx.
        assert a["confidence"] == e["confidence"]


@pytest.mark.parametrize("case", _EN_FROZEN, ids=[c["id"] for c in _EN_FROZEN])
def test_en_person_golden(case):
    actual = _run_en_case(case)
    expected = case["output"]
    assert len(actual) == len(expected), f"count mismatch for {case['id']}"
    for a, e in zip(actual, expected):
        assert a["text"] == e["text"]
        assert a["type"] == e["type"]
        assert a["start"] == e["start"]
        assert a["end"] == e["end"]
        assert a["confidence"] == e["confidence"]


if __name__ == "__main__":
    _regenerate()
