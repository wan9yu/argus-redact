"""Tests for risk assessment — pure function, no side effects."""

from argus_redact.pure.risk import RiskResult, assess_risk


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
        multiple = assess_risk(
            [
                {"type": "phone", "sensitivity": 3},
                {"type": "id_number", "sensitivity": 4},
            ]
        )
        assert multiple.score > single.score

    def test_should_amplify_when_dob_plus_address(self):
        dob_only = assess_risk([{"type": "date_of_birth", "sensitivity": 2}])
        dob_addr = assess_risk(
            [
                {"type": "date_of_birth", "sensitivity": 2},
                {"type": "address", "sensitivity": 2},
            ]
        )
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
        assert "PIPL Art.13" in result.pipl_articles
        assert "PIPL Art.28" in result.pipl_articles
        assert "PIPL Art.51" in result.pipl_articles
        assert "PIPL Art.29" in result.pipl_articles

    def test_should_include_art28_only_when_low_sensitivity(self):
        entities = [{"type": "ip_address", "sensitivity": 1}]
        result = assess_risk(entities)
        assert "PIPL Art.13" in result.pipl_articles
        assert "PIPL Art.28" in result.pipl_articles
        assert "PIPL Art.51" not in result.pipl_articles

    def test_should_include_impact_assessment_for_sensitive_types(self):
        entities = [{"type": "medical", "sensitivity": 3}]
        result = assess_risk(entities)
        assert "PIPL Art.55" in result.pipl_articles

    def test_should_include_record_keeping(self):
        entities = [{"type": "phone", "sensitivity": 3}]
        result = assess_risk(entities)
        assert "PIPL Art.56" in result.pipl_articles

    def test_should_generate_reasons(self):
        entities = [
            {"type": "id_number", "sensitivity": 4},
            {"type": "phone", "sensitivity": 3},
        ]
        result = assess_risk(entities)
        assert len(result.reasons) >= 1

    def test_should_amplify_when_self_reference_with_medical(self):
        """self_reference + medical should score higher than medical alone."""
        medical_only = assess_risk([{"type": "medical", "sensitivity": 3}])
        with_self = assess_risk(
            [
                {"type": "medical", "sensitivity": 3},
                {"type": "self_reference", "sensitivity": 2},
            ]
        )
        assert with_self.score > medical_only.score
        assert "self-reference amplification" in " ".join(with_self.reasons)

    def test_should_amplify_when_self_reference_with_financial(self):
        """self_reference + financial should amplify."""
        financial_only = assess_risk([{"type": "financial", "sensitivity": 3}])
        with_self = assess_risk(
            [
                {"type": "financial", "sensitivity": 3},
                {"type": "self_reference", "sensitivity": 2},
            ]
        )
        assert with_self.score > financial_only.score

    def test_result_is_frozen_dataclass(self):
        result = assess_risk([])
        assert isinstance(result, RiskResult)


class TestComplianceMetadataFields:
    """v0.5.9: assess_risk reads PIPL/GDPR/HIPAA metadata from PIITypeDef
    rather than the previous hardcoded inference. New RiskResult fields
    aggregate the metadata across all entities present.

    Existing 14 tests above MUST still pass — the migration preserves
    behavior exactly. These tests cover the new fields.
    """

    def test_should_expose_gdpr_special_category(self):
        # medical is GDPR Art.9 special category
        result = assess_risk([{"type": "medical", "sensitivity": 4}])
        assert result.gdpr_special_category is True

    def test_should_clear_gdpr_special_when_no_special_types(self):
        result = assess_risk([{"type": "phone", "sensitivity": 3}])
        assert result.gdpr_special_category is False

    def test_should_expose_hipaa_categories(self):
        result = assess_risk(
            [
                {"type": "phone", "sensitivity": 3},
                {"type": "medical", "sensitivity": 4},
            ]
        )
        assert "phone_numbers" in result.hipaa_categories
        assert "medical_record" in result.hipaa_categories

    def test_should_have_empty_hipaa_categories_for_non_phi_types(self):
        # qq is a Chinese-specific type with no HIPAA mapping
        result = assess_risk([{"type": "qq", "sensitivity": 2}])
        assert result.hipaa_categories == ()

    def test_empty_entities_have_empty_compliance_fields(self):
        result = assess_risk([])
        assert result.gdpr_special_category is False
        assert result.hipaa_categories == ()
