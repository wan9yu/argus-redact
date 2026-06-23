"""Evidence-gated hobby detector — precision + recall floors.

Hobbies are detected (type "hobby", default strategy remove) ONLY with an interest
cue (爱好/喜欢/经常/平时/擅长) or PII proximity, so an activity word in a non-personal
context (攀岩很难 / 书法是传统艺术) is not over-redacted. Floors, not exact match.
"""
from argus_redact import redact

_SALT = b"hobby-floor-test-salt-aaaaaaaaaa!"

def _detects(text: str) -> bool:
    out, _ = redact(text, mode="fast", lang=["zh"], salt=_SALT,
                    config={"hobby": {"strategy": "category"}})
    return "[hobby]" in out or "[HOBBY]" in out

POSITIVES = ["我喜欢攀岩。", "她爱好书法。", "周末他经常钓鱼。", "我平时喜欢瑜伽。", "他擅长围棋。"]
NEGATIVES = ["攀岩很难。", "这个项目很难。", "书法是传统艺术。", "今天天气不错。", "篮球比赛很精彩。"]

def test_hobby_precision_floor():
    fps = [t for t in NEGATIVES if _detects(t)]
    assert fps == [], f"hobby false-positives (must be 0): {fps}"

def test_hobby_recall_floor():
    hits = sum(1 for t in POSITIVES if _detects(t))
    assert hits >= 4, f"hobby recall floor 4/5: only {hits}/{len(POSITIVES)}"
