"""Risk assessment — pure function that scores privacy risk from detected entities."""

from __future__ import annotations

from dataclasses import dataclass

# Sensitivity level labels
_LEVEL_LABELS = {1: "low", 2: "medium", 3: "high", 4: "critical"}

# Quasi-identifier combinations that amplify risk
_QUASI_ID_COMBOS = [
    {"date_of_birth", "address"},
    {"date_of_birth", "phone"},
    {"address", "phone"},
]

# PIPL article mapping
_PIPL_ART_13 = "PIPL Art.13"  # Lawful basis for processing personal information
_PIPL_ART_28 = "PIPL Art.28"  # De-identification requirement (any PII)
_PIPL_ART_29 = "PIPL Art.29"  # Separate consent for sensitive PI
_PIPL_ART_51 = "PIPL Art.51"  # Sensitive personal information definition
_PIPL_ART_55 = "PIPL Art.55"  # Personal information protection impact assessment
_PIPL_ART_56 = "PIPL Art.56"  # Record-keeping obligation for PI processors

# Types that trigger specific PIPL articles beyond the baseline
_SENSITIVE_PI_TYPES = {
    "medical",
    "financial",
    "religion",
    "political",
    "sexual_orientation",
    "criminal_record",
    "biometric",
}


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

    # Self-reference amplification: "我" + any sensitive type = directly about user
    if "self_reference" in types_found:
        sensitive_with_self = types_found & (
            _SENSITIVE_PI_TYPES | {"phone", "id_number", "bank_card"}
        )
        if sensitive_with_self:
            score += 0.15
            reasons.append("self-reference amplification: PII directly linked to user")

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
    pipl = [_PIPL_ART_13, _PIPL_ART_28]  # any PII triggers lawful basis + de-identification
    if max_sens >= 3:
        pipl.append(_PIPL_ART_51)  # sensitive PI definition
        pipl.append(_PIPL_ART_29)  # separate consent required
    if len(entities) >= 3 or any(e["type"] in _SENSITIVE_PI_TYPES for e in entities):
        pipl.append(_PIPL_ART_55)  # impact assessment required
    pipl.append(_PIPL_ART_56)  # record-keeping obligation (always applies when PII found)

    return RiskResult(
        score=round(score, 2),
        level=level,
        entities=tuple({"type": e["type"], "sensitivity": e["sensitivity"]} for e in entities),
        reasons=tuple(reasons),
        pipl_articles=tuple(pipl),
    )
