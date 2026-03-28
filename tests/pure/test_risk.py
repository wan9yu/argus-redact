"""Tests for risk assessment — pure function, no side effects."""

from argus_redact.pure.risk import assess_risk, RiskResult


class TestAssessRisk:
    def test_should_return_low_when_no_entities(self):
        result = assess_risk([])
        assert result.score == 0.0
        assert result.level == "none"
        assert result.reasons == ()

    def test_should_return_medium_when_single_email(self):
        entities = [{"type": "email", "sensitivity": 2}]
        result = assess_risk(entities)
        assert result.level == "medium"
        assert result.score == 0.5

    def test_should_return_critical_when_id_number(self):
        entities = [{"type": "id_number", "sensitivity": 4}]
        result = assess_risk(entities)
        assert result.level == "critical"
        assert result.score >= 0.85

    def test_should_amplify_when_multiple_high_entities(self):
        single = assess_risk([{"type": "phone", "sensitivity": 3}])
        multiple = assess_risk([
            {"type": "phone", "sensitivity": 3},
            {"type": "id_number", "sensitivity": 4},
        ])
        assert multiple.score > single.score

    def test_should_amplify_when_dob_plus_address(self):
        dob_only = assess_risk([{"type": "date_of_birth", "sensitivity": 2}])
        dob_addr = assess_risk([
            {"type": "date_of_birth", "sensitivity": 2},
            {"type": "address", "sensitivity": 2},
        ])
        assert dob_addr.score > dob_only.score

    def test_should_cap_score_at_1(self):
        entities = [
            {"type": "id_number", "sensitivity": 4},
            {"type": "bank_card", "sensitivity": 4},
            {"type": "phone", "sensitivity": 3},
            {"type": "address", "sensitivity": 2},
            {"type": "date_of_birth", "sensitivity": 2},
        ]
        result = assess_risk(entities)
        assert result.score <= 1.0

    def test_should_include_pipl_articles_when_sensitive(self):
        entities = [{"type": "id_number", "sensitivity": 4}]
        result = assess_risk(entities)
        assert "PIPL Art.28" in result.pipl_articles
        assert "PIPL Art.51" in result.pipl_articles

    def test_should_include_art28_only_when_low_sensitivity(self):
        entities = [{"type": "ip_address", "sensitivity": 1}]
        result = assess_risk(entities)
        assert "PIPL Art.28" in result.pipl_articles
        assert "PIPL Art.51" not in result.pipl_articles

    def test_should_generate_reasons(self):
        entities = [
            {"type": "id_number", "sensitivity": 4},
            {"type": "phone", "sensitivity": 3},
        ]
        result = assess_risk(entities)
        assert len(result.reasons) >= 1

    def test_result_is_frozen_dataclass(self):
        result = assess_risk([])
        assert isinstance(result, RiskResult)
