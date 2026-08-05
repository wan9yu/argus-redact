"""The shared wire projections must not silently drop a field.

`risk` was hand-built in two faces and both dropped `gdpr_special_category`,
`hipaa_categories` and `reasons` — a compliance field invisible to every caller
for three minor versions. One projection with a field-set gate is what stops the
next `RiskResult` field going the same way.
"""

from __future__ import annotations

import dataclasses
import json

from argus_redact._types import CoverageAdvisory, RedactReport
from argus_redact.pure.risk import RiskResult
from argus_redact.pure.wire import common_report_fields, coverage_payload, risk_payload


def _a_risk() -> RiskResult:
    return RiskResult(
        score=0.7,
        level="high",
        entities=({"type": "phone", "original": "13812345678"},),
        reasons=("contains phone",),
        pipl_articles=("Art.28",),
        gdpr_special_category=True,
        hipaa_categories=("PHI",),
    )


def test_risk_payload_covers_every_riskresult_field_except_entities():
    declared = {f.name for f in dataclasses.fields(RiskResult)}
    assert set(risk_payload(_a_risk())) == declared - {"entities"}, (
        "RiskResult gained or lost a field. Add it to risk_payload (or, if it must "
        "stay off the wire, exclude it here and say why in the docstring) — do not "
        "leave it undeclared."
    )


def test_risk_payload_omits_entities_so_it_cannot_route_around_a_face_decision():
    payload = risk_payload(_a_risk())
    assert "entities" not in payload
    assert "13812345678" not in json.dumps(payload, ensure_ascii=False)


def test_risk_payload_is_json_serialisable():
    json.dumps(risk_payload(_a_risk()), ensure_ascii=False)


def test_coverage_payload_covers_every_advisory_field():
    declared = {f.name for f in dataclasses.fields(CoverageAdvisory)}
    payload = coverage_payload(CoverageAdvisory(uncovered=("sex",), narrow=("age",)))
    assert set(payload) == declared
    json.dumps(payload, ensure_ascii=False)


def test_coverage_payload_passes_none_through():
    assert coverage_payload(None) is None


def test_common_report_fields_covers_exactly_the_four_shared_keys():
    report = RedactReport(redacted_text="", key={})
    assert set(common_report_fields(report)) == {
        "residual_personal_data",
        "security_events",
        "coverage",
        "layers_used",
    }
