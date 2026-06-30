"""Offline structural + non-vacuity test for the PRvL+ multi-model runner.

Monkeypatches ``prvl_multi_eval.call_llm`` so the whole run executes with NO
network access (no real OpenRouter request) and asserts:

  * the row schema carries every field the baker + paper consume,
  * the aggregate is present and keyed ``"<model> / <profile>"``,
  * Privacy is NON-VACUOUS — a stub that echoes an original PII value makes
    ``privacy.leaked`` contain it, while a clean stub leaves it ``[]``,
  * Utility-basic is NON-VACUOUS — a refusal stub scores ``0.0``, a normal
    answer scores ``1.0``,
  * a parseable JSON snapshot is written to the requested ``--out`` path.
"""

from __future__ import annotations

import json

from tests.benchmark import prvl_multi_eval

# case[0] (summarize_zh) carries this original PII; an echoing stub must leak it.
_LEAKED_PII = "13812345678"

_REQUIRED_ROW_FIELDS = {
    "case_id",
    "profile",
    "model",
    "redacted",
    "output",
    "privacy",
    "reversibility",
    "utility",
    "utility_judge",
    "task_type",
    "completion",
    "is_refusal",
    "expected_safety_refusal",
}


def _run(monkeypatch, tmp_path, reply: str, name: str) -> tuple[dict, "object"]:
    monkeypatch.setattr(prvl_multi_eval, "call_llm", lambda *a, **k: reply)
    out = tmp_path / f"prvl_{name}.json"
    snap = prvl_multi_eval.run(models=["GPT-5"], profiles=["default"], limit=2, out=out)
    return snap, out


def test_schema_and_aggregate(tmp_path, monkeypatch):
    snap, out = _run(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        reply="This is a clean, useful answer with no secrets at all.",
        name="schema",
    )

    assert snap["benchmark"] == "prvl_multi"
    assert snap["provider"] == "openrouter"
    assert snap["cases"] == 2
    assert snap["rows"], "no rows produced"
    for row in snap["rows"]:
        assert _REQUIRED_ROW_FIELDS <= set(row), f"row missing fields: {row.keys()}"
        assert set(row["privacy"]) >= {"leaked", "total"}
        assert 0.0 <= row["reversibility"] <= 1.0
        assert row["utility"] in (0.0, 1.0)

    assert "GPT-5 / default" in snap["aggregate"]
    agg = snap["aggregate"]["GPT-5 / default"]
    assert set(agg) >= {
        "leak_rate",
        "reversibility",
        "utility_completed",
        "refusal_rate",
        "utility_judge",
        "n",
    }
    assert agg["n"] == 2

    # snapshot file is real, parseable JSON
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["benchmark"] == "prvl_multi"


def test_privacy_non_vacuous(tmp_path, monkeypatch):
    # The stub echoes case[0]'s original PII but NOT case[1]'s → leak in one,
    # clean in the other, proving the privacy metric reacts both directions.
    snap, _ = _run(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        reply=f"Patient contact number is {_LEAKED_PII}, please follow up.",
        name="leak",
    )
    by_case = {r["case_id"]: r for r in snap["rows"]}

    leaking = by_case["summarize_zh"]
    assert _LEAKED_PII in leaking["privacy"]["leaked"], "echoed PII not flagged as leaked"

    clean = by_case["translate_zh_en"]
    assert clean["privacy"]["leaked"] == [], "clean output wrongly flagged as a leak"


def test_utility_basic_non_vacuous(tmp_path, monkeypatch):
    refusal, _ = _run(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        reply="I'm sorry, I cannot help with that request.",
        name="refusal",
    )
    assert all(r["utility"] == 0.0 for r in refusal["rows"]), "refusal scored as usable"
    # T2: refusal is classified distinctly (not conflated with empty) + surfaced.
    assert all(r["completion"] == "refusal" and r["is_refusal"] for r in refusal["rows"])
    assert all(a["refusal_rate"] == 1.0 for a in refusal["aggregate"].values())

    answered, _ = _run(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        reply="Here is a concise and complete summary of the record.",
        name="answer",
    )
    assert all(r["utility"] == 1.0 for r in answered["rows"]), "normal answer scored unusable"
    assert all(r["completion"] == "completed" and not r["is_refusal"] for r in answered["rows"])
    assert all(a["refusal_rate"] == 0.0 for a in answered["aggregate"].values())


def test_expected_safety_refusal_tag():
    # T2: health-extract / health-advice cases are tagged so a frontier-model safety
    # refusal there is separable from a task argus actually broke. Covers both the
    # legacy pair and the expanded fixture corpus' health cases.
    cases = {c["id"]: c for c in prvl_multi_eval._default_cases()}
    for cid in ("qa_en", "advice_zh", "extract_condition_zh", "advice_condition_en"):
        assert cases[cid]["expected_safety_refusal"] is True
    assert cases["summarize_zh"]["expected_safety_refusal"] is False


def test_default_cases_expanded_balanced_wellformed():
    # The PRvL+ matrix must be statistically meaningful, not the legacy N=4 toy set.
    # Lock in: >=24 unique cases, a {text} slot in every prompt, every declared PII
    # substring actually present in its own text, and a balanced spread across the
    # three task families (reference / extract / creative) and the two languages.
    from collections import Counter

    cases = prvl_multi_eval._default_cases()
    assert len(cases) >= 24, f"expected >= 24 merged cases, got {len(cases)}"

    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids after merge"

    for c in cases:
        assert "{text}" in c["prompt"], f"{c['id']}: prompt missing {{text}} slot"
        assert c["task_type"] in {"reference", "extract", "creative", "unknown"}
        for p in c["pii"]:
            assert p in c["text"], f"{c['id']}: pii {p!r} not present in its text"

    by_type = Counter(c["task_type"] for c in cases)
    for t in ("reference", "extract", "creative"):
        assert by_type[t] >= 7, f"task_type {t} underrepresented for balance: {by_type}"

    by_lang = Counter(c["lang"] for c in cases if isinstance(c["lang"], str))
    assert by_lang["zh"] >= 10 and by_lang["en"] >= 10, f"language skew: {by_lang}"


def test_null_content_does_not_crash(tmp_path, monkeypatch):
    # A model returning null content (finish_reason=length / content filter) must NOT
    # abort the matrix (the bug that lost a full paid run) — it counts as an empty,
    # unusable answer: output "", utility 0.0, no leak.
    snap, _ = _run(tmp_path=tmp_path, monkeypatch=monkeypatch, reply=None, name="null")
    assert snap["rows"], "no rows produced"
    for r in snap["rows"]:
        assert r["output"] == ""
        assert r["utility"] == 0.0
        assert r["completion"] == "empty" and not r["is_refusal"]
        assert r["privacy"]["leaked"] == []
