"""Evidence-gated region detector — precision + recall floors.

Bare admin regions are detected ONLY with address-context evidence, so location
quasi-identifiers can be generalized/removed while region names in non-PII
contexts (time/org/food/landmark) are NOT over-redacted. Floors, not exact match
(the gate is a heuristic). cf. the person-detector precision/recall floors.
"""
from argus_redact import redact


def _detects_region(text: str) -> bool:
    # category strategy → a detected location becomes "[location]"; visible marker.
    out, _ = redact(text, mode="fast", lang=["zh"], salt=42,
                    config={"location": {"strategy": "category"}})
    return "[location]" in out or "[LOCATION]" in out


# Positives: a real gazetteer region + an address-context cue → SHOULD detect.
POSITIVES = [
    "他住在上海浦东新区，平时挺忙的。",
    "我家住杭州西湖区，离公司很近。",
    "户籍地在广州天河区。",
    "我在深圳南山区租房，房租不便宜。",
    "老家是成都武侯区的。",
]
# Negatives: a region name (or near-region) in a NON-PII context → must NOT detect.
NEGATIVES = [
    "现在是北京时间晚上八点。",
    "他考上了北京大学，全家很高兴。",
    "周末我们去吃北京烤鸭吧。",
    "上海合作组织今天举行会议。",
    "西湖醋鱼是杭州名菜。",
    "这家公司在朝阳群众的监督下整改。",
    "广州塔是地标建筑。",
]


def test_region_precision_floor():
    fps = [t for t in NEGATIVES if _detects_region(t)]
    assert fps == [], f"region detector false-positives (must be 0): {fps}"


def test_region_recall_floor():
    hits = sum(1 for t in POSITIVES if _detects_region(t))
    assert hits >= 4, f"region recall floor 4/5: only {hits}/{len(POSITIVES)} detected"
