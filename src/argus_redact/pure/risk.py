"""Risk assessment — pure function that scores privacy risk from detected entities."""

from __future__ import annotations

from dataclasses import dataclass, field

# Sensitivity level labels
_LEVEL_LABELS = {1: "low", 2: "medium", 3: "high", 4: "critical"}

# Quasi-identifier combinations that amplify risk
_QUASI_ID_COMBOS = [
    {"date_of_birth", "address"},
    {"date_of_birth", "phone"},
    {"address", "phone"},
]

# PIPL article mapping
_PIPL_ART_28 = "PIPL Art.28"  # De-identification requirement (any PII)
_PIPL_ART_51 = "PIPL Art.51"  # Sensitive personal information (sensitivity >= 3)


@dataclass(frozen=True)
class RiskResult:
    score: float
    level: str
    entities: tuple[dict, ...] = ()
    reasons: tuple[str, ...] = ()
    pipl_articles: tuple[str, ...] = ()


def assess_risk(entities: list[dict], lang: str = "zh") -> RiskResult:
    """Assess privacy risk from a list of detected entities.

    Each entity dict must have 'type' and 'sensitivity' keys.
    Returns a RiskResult with score (0.0-1.0), level, reasons, and PIPL articles.
    """
    if not entities:
        return RiskResult(score=0.0, level="none")

    # Base score = max sensitivity / 4
    max_sens = max(e["sensitivity"] for e in entities)
    score = max_sens / 4.0

    reasons = []
    types_found = {e["type"] for e in entities}

    # Reason for each unique type
    for e in entities:
        label = _LEVEL_LABELS.get(e["sensitivity"], "unknown")
        reason = f"{e['type']} ({label})"
        if reason not in reasons:
            reasons.append(reason)

    # Combination amplification: multiple high/critical entities
    high_critical = [e for e in entities if e["sensitivity"] >= 3]
    if len(high_critical) >= 2:
        score += 0.1
        reasons.append("multiple high/critical entities detected")

    # Quasi-identifier combination amplification
    for combo in _QUASI_ID_COMBOS:
        if combo.issubset(types_found):
            score += 0.1
            reasons.append(f"quasi-identifier combination: {' + '.join(sorted(combo))}")
            break  # only one combo bonus

    score = min(score, 1.0)

    # Level mapping
    if score < 0.3:
        level = "low"
    elif score < 0.6:
        level = "medium"
    elif score < 0.85:
        level = "high"
    else:
        level = "critical"

    # PIPL articles
    pipl = [_PIPL_ART_28]  # any PII triggers Art.28
    if max_sens >= 3:
        pipl.append(_PIPL_ART_51)

    return RiskResult(
        score=round(score, 2),
        level=level,
        entities=tuple({"type": e["type"], "sensitivity": e["sensitivity"]} for e in entities),
        reasons=tuple(reasons),
        pipl_articles=tuple(pipl),
    )
