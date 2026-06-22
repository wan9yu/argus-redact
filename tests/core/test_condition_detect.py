"""Evidence-gated condition/allergy detector — precision + recall floors.

Conditions/allergens are detected (type "medical", default strategy remove) ONLY
with a health cue (过敏/患有/确诊…) or PII proximity, so food words in non-health
contexts (我喜欢吃花生 / 海鲜大餐很美味) are not over-redacted. Floors, not exact match.

NB: the NEGATIVES deliberately avoid the pre-existing data/zh.ron *medication*
regex's weak `吃的`/`吃了` triggers (`吃了海鲜大餐` over-matches via that legacy
pattern, independent of this detector). This test pins THIS detector's precision;
the legacy 吃了/吃的 over-match is tracked separately.
"""
from argus_redact import redact

_SALT = b"condition-floor-test-salt-32byte!"

def _detects(text: str) -> bool:
    out, _ = redact(text, mode="fast", lang=["zh"], salt=_SALT,
                    config={"medical": {"strategy": "category"}})
    return "[medical]" in out or "[MEDICAL]" in out

POSITIVES = ["我对花生严重过敏。", "她对海鲜过敏。", "他确诊了糖尿病。", "有高血压病史。", "我对青霉素过敏。"]
NEGATIVES = ["我喜欢吃花生。", "海鲜大餐很美味。", "这道菜很好吃。", "牛奶很有营养。", "花粉季节到了。"]

def test_condition_precision_floor():
    fps = [t for t in NEGATIVES if _detects(t)]
    assert fps == [], f"condition false-positives (must be 0): {fps}"

def test_condition_recall_floor():
    hits = sum(1 for t in POSITIVES if _detects(t))
    assert hits >= 4, f"condition recall floor 4/5: only {hits}/{len(POSITIVES)}"
