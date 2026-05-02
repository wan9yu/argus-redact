"""Risk assessment — pure function that scores privacy risk from detected entities.

PIPL/GDPR/HIPAA classification is sourced from `PIITypeDef` metadata (v0.5.9+);
the previous hardcoded inference rules are now centralized in
`specs/_compliance.py` so downstream DPIA generators can read the same data
via `argus_redact.specs.get(...)` without mirroring rules.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass

from argus_redact.specs._compliance import (
    PIPL_ART_13,
    PIPL_ART_28,
    PIPL_ART_29,
    PIPL_ART_51,
    PIPL_ART_55,
    PIPL_ART_56,
    PIPL_SENSITIVE_PI,
)
from argus_redact.specs.registry import get as _registry_get
from argus_redact.specs.registry import lookup as _registry_lookup

# Sensitivity level labels
_LEVEL_LABELS = {1: "low", 2: "medium", 3: "high", 4: "critical"}

# Quasi-identifier combinations that amplify the risk *score*. (Compliance
# article assignment lives on PIITypeDef now; this set is purely for scoring.)
_QUASI_ID_COMBOS = [
    {"date_of_birth", "address"},
    {"date_of_birth", "phone"},
    {"address", "phone"},
]

# Types that amplify the risk score when combined with self_reference.
# Composed from the central PIPL_SENSITIVE_PI set plus three structural-PII
# types — keeps the score rule in sync with the compliance classification.
_SELF_REF_AMPLIFY_WITH = PIPL_SENSITIVE_PI | {"phone", "id_number", "bank_card"}

# Stable output ordering for `pipl_articles` matching pre-v0.5.9 list order
# (Art.13, 28, 51, 29, 55, 56 — the canonical legal sequence, not numerical).
_PIPL_SORT_ORDER = {
    PIPL_ART_13: 0,
    PIPL_ART_28: 1,
    PIPL_ART_51: 2,
    PIPL_ART_29: 3,
    PIPL_ART_55: 4,
    PIPL_ART_56: 5,
}


@dataclass(frozen=True)
class RiskResult:
    score: float
    level: str
    entities: tuple[dict, ...] = ()
    reasons: tuple[str, ...] = ()
    pipl_articles: tuple[str, ...] = ()
    gdpr_special_category: bool = False  # v0.5.9+
    hipaa_categories: tuple[str, ...] = ()  # v0.5.9+


@functools.lru_cache(maxsize=512)
def _lookup_typedef(type_name: str, lang: str):
    """Resolve a typedef by (lang, name), falling back to any-lang lookup.

    Cached because `assess_risk()` may iterate many entities of the same type
    (a long form with 50 phone numbers shouldn't do 50 dict lookups). The
    registry is frozen at import, so caching is safe.
    """
    try:
        return _registry_get(lang, type_name)
    except KeyError:
        candidates = _registry_lookup(type_name)
        return candidates[0] if candidates else None


def assess_risk(entities: list[dict], lang: str = "zh") -> RiskResult:
    """Assess privacy risk from a list of detected entities.

    Each entity dict must have 'type' and 'sensitivity' keys.
    Returns a RiskResult with score (0.0-1.0), level, reasons, and PIPL articles
    plus GDPR Art.9 / HIPAA category aggregates (v0.5.9+).
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
        sensitive_with_self = types_found & _SELF_REF_AMPLIFY_WITH
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

    # ── Compliance metadata aggregation (v0.5.9+) ──
    # Read PIPL articles, GDPR special-category flag, and HIPAA category from
    # each entity's PIITypeDef. Skips entities whose type isn't in the
    # registry (e.g., test fixtures with arbitrary type names).
    pipl_set: set[str] = set()
    gdpr_special = False
    hipaa_set: set[str] = set()

    for e in entities:
        td = _lookup_typedef(e["type"], lang)
        if td is None:
            continue
        pipl_set.update(td.pipl_articles)
        if td.gdpr_special_category:
            gdpr_special = True
        if td.hipaa_phi_category:
            hipaa_set.add(td.hipaa_phi_category)

    # Cardinality rule: ≥ 3 entities → impact assessment required (Art.55).
    # Independent of typedef so a high-volume single-type query still
    # triggers it.
    if len(entities) >= 3:
        pipl_set.add("PIPL Art.55")

    pipl_articles = tuple(
        sorted(pipl_set, key=lambda art: _PIPL_SORT_ORDER.get(art, 999))
    )

    return RiskResult(
        score=round(score, 2),
        level=level,
        entities=tuple({"type": e["type"], "sensitivity": e["sensitivity"]} for e in entities),
        reasons=tuple(reasons),
        pipl_articles=pipl_articles,
        gdpr_special_category=gdpr_special,
        hipaa_categories=tuple(sorted(hipaa_set)),
    )
