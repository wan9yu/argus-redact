"""Risk assessment — thin shim over the Rust `_core.assess_risk` (v0.7.8+).

Scoring, PIPL/GDPR/HIPAA aggregation, and the compliance data now live in Rust
(`argus-redact-core::risk`, data generated from the registry SSOT). This module
keeps the public `assess_risk` signature and the frozen `RiskResult` dataclass.
"""

from __future__ import annotations

from dataclasses import dataclass

from argus_redact._core_loader import _core


@dataclass(frozen=True)
class RiskResult:
    score: float
    level: str
    entities: tuple[dict, ...] = ()
    reasons: tuple[str, ...] = ()
    pipl_articles: tuple[str, ...] = ()
    gdpr_special_category: bool = False  # v0.5.9+
    gdpr_art10: bool = False  # v0.8.10+ — GDPR Art.10 (criminal convictions/offences)
    hipaa_categories: tuple[str, ...] = ()  # v0.5.9+


def assess_risk(entities: list[dict], lang: str = "zh") -> RiskResult:
    """Assess privacy risk from a list of detected entities.

    Each entity dict must have 'type' and 'sensitivity' keys. Returns a
    RiskResult with score (0.0-1.0), level, reasons, PIPL articles, and the
    GDPR Art.9 / HIPAA category aggregates.
    """
    if not entities:
        return RiskResult(score=0.0, level="none")

    score, level, ents, reasons, pipl, gdpr, hipaa, gdpr_art10 = _core.assess_risk(
        [(e["type"], e["sensitivity"]) for e in entities], lang
    )
    return RiskResult(
        score=score,
        level=level,
        entities=tuple({"type": t, "sensitivity": s} for t, s in ents),
        reasons=tuple(reasons),
        pipl_articles=tuple(pipl),
        gdpr_special_category=gdpr,
        gdpr_art10=gdpr_art10,
        hipaa_categories=tuple(hipaa),
    )
