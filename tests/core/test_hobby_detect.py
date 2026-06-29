"""Evidence-gated hobby detector — precision + recall floors.

Hobbies are detected (type "hobby", default strategy remove) ONLY with an interest
cue (爱好/喜欢/经常/平时/擅长) or PII proximity, so an activity word in a non-personal
context (攀岩很难 / 书法是传统艺术) is not over-redacted. Floors, not exact match.
"""

from argus_redact import redact

_SALT = b"hobby-floor-test-salt-aaaaaaaaaa!"


def _detects(text: str) -> bool:
    out, _ = redact(
        text, mode="fast", lang=["zh"], salt=_SALT, config={"hobby": {"strategy": "category"}}
    )
    return "[hobby]" in out or "[HOBBY]" in out


POSITIVES = ["我喜欢攀岩。", "她爱好书法。", "周末他经常钓鱼。", "我平时喜欢瑜伽。", "他擅长围棋。"]
NEGATIVES = [
    "攀岩很难。",
    "这个项目很难。",
    "书法是传统艺术。",
    "今天天气不错。",
    "篮球比赛很精彩。",
]


def test_hobby_precision_floor():
    fps = [t for t in NEGATIVES if _detects(t)]
    assert fps == [], f"hobby false-positives (must be 0): {fps}"


def test_hobby_recall_floor():
    hits = sum(1 for t in POSITIVES if _detects(t))
    assert hits >= 4, f"hobby recall floor 4/5: only {hits}/{len(POSITIVES)}"


# ---------------------------------------------------------------------------
# Proximity-allowlist fix: technical PII must not corroborate a hobby
# ---------------------------------------------------------------------------


def test_hobby_technical_pii_only_not_corroborated():
    # api-key (anthropic_api_key sk-ant-... format) is technical/non-personal; after the
    # proximity-allowlist fix it no longer corroborates an evidence-gated hobby.
    # 乒乓球 (3-char, in hobby lexicon) scores lexicon weight 0.3 but gets no
    # proximity boost from an api-key-only context (0.3 + 0 < 0.5 threshold)
    # → NOT detected.  Uses 乒乓球 rather than 攀岩: 攀岩 is 2-char, so
    # DEFAULT_LEXICON_CONF_MIN is not met and proximity is always insufficient
    # for it regardless of PII type — making 攀岩 a guard only.  乒乓球
    # demonstrates the actual fix (api-key excluded from allowlist).
    assert not _detects("乒乓球 sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA"), (
        "api-key must not corroborate an evidence-gated hobby (no cue)"
    )


def test_hobby_personal_pii_still_corroborates():
    # phone IS person-identifying; it still promotes 乒乓球 via proximity
    # (lexicon 0.3 + phone-prox 0.3 = 0.6 ≥ 0.5 threshold) → IS detected.
    # Regression guard: the fix must not break the phone-proximity path.
    assert _detects("乒乓球 13800138000"), "phone must still corroborate an evidence-gated hobby"


def test_hobby_mixed_technical_and_personal_pii():
    # api-key alone is excluded; phone still corroborates → IS detected.
    assert _detects("乒乓球 sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA 13800138000"), (
        "phone must still corroborate even when an api-key is also present"
    )
