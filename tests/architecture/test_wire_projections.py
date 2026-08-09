"""The shared wire projections must not silently drop a field.

`risk` was hand-built three times. The HTTP and MCP copies both dropped
`gdpr_special_category` and `hipaa_categories`, which shipped in v0.5.9 and
reached no caller until v0.8.8; the CLI copy dropped `reasons` on top of those.
One projection with a field-set gate is what stops the next `RiskResult` field
going the same way.
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
        gdpr_art10=True,
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


def test_common_report_fields_shares_no_mutable_state_with_the_report():
    """Every face spreads this helper into its envelope. If the projection kept
    the report's own event dicts, a face editing one would reach back into a
    frozen `RedactReport` — and `list()` alone is a shallow copy."""
    report = RedactReport(
        redacted_text="",
        key={},
        security_events=(
            {
                "type": "security",
                "reason_code": "keep_downgraded",
                "count": 1,
                "detail": "types: phone",
            },
        ),
    )
    first = common_report_fields(report)
    second = common_report_fields(report)
    assert first["security_events"] is not second["security_events"]
    for projected, original in zip(first["security_events"], report.security_events):
        assert projected is not original
        projected["detail"] = "TAMPERED"
        assert original["detail"] != "TAMPERED"


def test_common_report_fields_cannot_collide_with_a_face_specific_key():
    """Every face spreads this helper LAST, so a shared key that collided with
    one a face sets explicitly would silently win and the face-contract gate —
    a key-NAME comparison — would not notice the value changed."""
    report = RedactReport(redacted_text="", key={})
    face_specific = {
        "redacted",  # HTTP, MCP
        "key",  # HTTP
        "entities",  # HTTP, CLI
        "stats",  # HTTP, CLI, MCP
        "risk",  # all three
        "summary",  # CLI
        "compliance",  # CLI
        "entities_found",  # MCP
    }
    assert not (set(common_report_fields(report)) & face_specific)


def test_common_report_fields_covers_exactly_the_four_shared_keys():
    report = RedactReport(redacted_text="", key={})
    assert set(common_report_fields(report)) == {
        "residual_personal_data",
        "security_events",
        "coverage",
        "layers_used",
    }
