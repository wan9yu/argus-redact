"""Evidence-gated condition/allergy detector — precision + recall floors.

Conditions/allergens are detected (type "medical", default strategy remove) ONLY
with a health cue (过敏/患有/确诊…) or PII proximity, so food words in non-health
contexts (我喜欢吃花生 / 海鲜大餐很美味 / 今天吃了海鲜大餐) are not over-redacted.
Floors, not exact match.

`今天吃了海鲜大餐` also guards the medication-regex fix: the weak `吃的`/`吃了`
triggers now fire `medical` ONLY when the following term ends in a drug suffix
(药/片/胶囊…), so `吃了海鲜大餐` (ends 餐) stays un-redacted while a real
`吃的降压药` (ends 药) is still caught.
"""

from argus_redact import redact

_SALT = b"condition-floor-test-salt-32byte!"


def _detects(text: str) -> bool:
    out, _ = redact(
        text, mode="fast", lang=["zh"], salt=_SALT, config={"medical": {"strategy": "category"}}
    )
    return "[medical]" in out or "[MEDICAL]" in out


POSITIVES = [
    "我对花生严重过敏。",
    "她对海鲜过敏。",
    "他确诊了糖尿病。",
    "有高血压病史。",
    "我对青霉素过敏。",
]
NEGATIVES = [
    "我喜欢吃花生。",
    "海鲜大餐很美味。",
    "今天吃了海鲜大餐。",
    "这道菜很好吃。",
    "牛奶很有营养。",
    "花粉季节到了。",
]


def test_condition_precision_floor():
    fps = [t for t in NEGATIVES if _detects(t)]
    assert fps == [], f"condition false-positives (must be 0): {fps}"


def test_condition_recall_floor():
    hits = sum(1 for t in POSITIVES if _detects(t))
    assert hits >= 4, f"condition recall floor 4/5: only {hits}/{len(POSITIVES)}"


# ---------------------------------------------------------------------------
# Proximity-allowlist fix: technical PII must not corroborate a condition
# ---------------------------------------------------------------------------


def test_condition_technical_pii_only_not_corroborated():
    # jwt is a technical/non-personal token; after the proximity-allowlist fix
    # it no longer corroborates an evidence-gated condition.  焦虑症 (3-char,
    # in the framework lexicon) scores lexicon weight 0.3 but gets no proximity
    # boost from a jwt-only context (0 + 0.3 < 0.5 threshold) → NOT detected.
    # Uses 焦虑症 rather than 糖尿病: 糖尿病 is also caught by a standalone
    # zh.ron regex that fires independently of the proximity path, so it would
    # always be redacted and could not demonstrate the proximity fix.
    assert not _detects("焦虑症 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"), (
        "jwt must not corroborate an evidence-gated condition (no cue)"
    )


def test_condition_personal_pii_still_corroborates():
    # phone IS person-identifying; it still promotes 焦虑症 via proximity
    # (lexicon 0.3 + phone-prox 0.3 = 0.6 ≥ 0.5 threshold) → IS detected.
    # Regression guard: the fix must not break the phone-proximity path.
    assert _detects("焦虑症 13800138000"), (
        "phone must still corroborate an evidence-gated condition"
    )


def test_condition_mixed_technical_and_personal_pii():
    # jwt alone is excluded; phone still corroborates → IS detected.
    assert _detects("焦虑症 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc 13800138000"), (
        "phone must still corroborate even when a jwt is also present"
    )
