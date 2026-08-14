"""JSON-safe projections of report objects, shared by every wire face.

`server.py`, `cli/main.py` and `integrations/mcp_server.py` each build their own
envelope — deliberately, since their shapes differ and unifying them would be a
breaking change — but the projection of a single report FIELD must not differ
between them. Before this module the `risk` dict was hand-built in two of the
three faces, and both copies dropped `gdpr_special_category` and
`hipaa_categories` — shipped in v0.5.9, reaching no caller until v0.8.8. The
third face (the CLI) built a different subset again, dropping `reasons` as well.
Three independent hand-built projections of one dataclass is the shape that
produced that; there is now one.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argus_redact._types import CoverageAdvisory, RedactReport
    from argus_redact.pure.risk import RiskResult


def risk_payload(risk: RiskResult) -> dict:
    """Every ``RiskResult`` field except ``entities``.

    ``entities`` is excluded on purpose: it duplicates ``RedactReport.entities``,
    which is the field that owns those spans and the one each face decides about
    separately. The MCP face withholds them — ``entities[].original`` is raw
    plaintext and that envelope is read back into a model's context window — so a
    second copy nested inside ``risk`` would route straight around that decision.
    """
    return {
        "score": risk.score,
        "level": risk.level,
        "reasons": list(risk.reasons),
        "pipl_articles": list(risk.pipl_articles),
        "gdpr_special_category": risk.gdpr_special_category,
        "gdpr_art10": risk.gdpr_art10,
        "hipaa_categories": list(risk.hipaa_categories),
    }


def coverage_payload(coverage: CoverageAdvisory | None) -> dict | None:
    """``CoverageAdvisory`` as a plain dict.

    It is a frozen dataclass, which no JSON encoder accepts. ``None`` passes
    through so a face can emit ``null`` rather than omit the key — an absent key
    and "the advisory was not computed" are different facts.
    """
    if coverage is None:
        return None
    return dataclasses.asdict(coverage)


def common_report_fields(report: RedactReport) -> dict:
    """The report fields every wire face projects identically.

    All three faces emit these four under the same wire key with no per-face
    variation, so they live here rather than being copy-pasted three times: the
    face-contract gate compares key NAMES, and would not notice a copy that got
    the value transform wrong.

    The result shares no mutable state with ``report``. ``list()`` alone would
    be a shallow copy — the event dicts would still be the report's own, so a
    caller editing one would reach through into a frozen dataclass — hence the
    per-event ``dict()``.
    """
    return {
        "residual_personal_data": report.residual_personal_data,
        "security_events": [dict(event) for event in report.security_events],
        "coverage": coverage_payload(report.coverage),
        "layers_used": list(report.layers_used),
    }
