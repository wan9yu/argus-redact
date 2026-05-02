"""Architecture: PIITypeDef compliance metadata invariants.

Each PIITypeDef declares its PIPL/GDPR/HIPAA classification as data fields,
not derived from sensitivity alone. assess_risk() reads these fields directly,
so Gateway DPIA generators can `import argus_redact.specs.get(...)` and get
the same answer without mirroring rules.

The invariants here guard against drift: adding a new type or changing
sensitivity must keep the metadata consistent.
"""

from __future__ import annotations

import argus_redact.specs.en  # noqa: F401  ensure registry loaded
import argus_redact.specs.shared  # noqa: F401
import argus_redact.specs.zh  # noqa: F401
from argus_redact.specs.registry import PIITypeDef, list_types

# PIPL Art.28 sensitive personal information categories — match the
# pre-migration `_SENSITIVE_PI_TYPES` set exactly. Used to verify Art.55
# (impact assessment) coverage.
_PIPL_SENSITIVE_TYPES = {
    "medical",
    "financial",
    "religion",
    "political",
    "sexual_orientation",
    "criminal_record",
    "biometric",
}

# Credentials and secrets are not personal data — they should not carry
# GDPR special-category or HIPAA flags even if highly sensitive.
_CREDENTIAL_TYPES = {
    "openai_api_key",
    "anthropic_api_key",
    "aws_access_key",
    "github_token",
    "jwt",
    "ssh_private_key",
}

# HIPAA Safe Harbor 18 PHI categories used in this project. Not every
# category needs to map to an argus-redact type — the test only checks that
# every value used in a typedef is one of these.
_HIPAA_SAFE_HARBOR_CATEGORIES = {
    "names",
    "geographic",
    "dates",
    "phone_numbers",
    "fax_numbers",
    "email_addresses",
    "ssn",
    "medical_record",
    "account_numbers",
    "certificate_number",
    "vehicle_identifier",
    "device_identifier",
    "biometric",
    "ip_address",
    "url",
    "full_face_photo",
    "other_unique_identifier",
}


class TestUniversalPIPLArticles:
    def test_every_pii_type_includes_art_13(self):
        # PIPL Art.13: lawful basis for processing — universal for any PII.
        for td in list_types():
            assert "PIPL Art.13" in td.pipl_articles, (
                f"{td.lang}/{td.name} missing PIPL Art.13"
            )

    def test_every_pii_type_includes_art_28(self):
        # PIPL Art.28: de-identification requirement — universal.
        for td in list_types():
            assert "PIPL Art.28" in td.pipl_articles, (
                f"{td.lang}/{td.name} missing PIPL Art.28"
            )

    def test_every_pii_type_includes_art_56(self):
        # PIPL Art.56: record-keeping obligation — universal.
        for td in list_types():
            assert "PIPL Art.56" in td.pipl_articles, (
                f"{td.lang}/{td.name} missing PIPL Art.56"
            )


class TestSensitivityDrivenPIPLArticles:
    def test_sensitivity_3plus_triggers_art_51_and_29(self):
        # PIPL Art.51 (sensitive PI definition) + Art.29 (separate consent)
        # apply when sensitivity >= 3.
        for td in list_types():
            if td.sensitivity >= 3:
                assert "PIPL Art.51" in td.pipl_articles, (
                    f"{td.lang}/{td.name} sens={td.sensitivity} missing Art.51"
                )
                assert "PIPL Art.29" in td.pipl_articles, (
                    f"{td.lang}/{td.name} sens={td.sensitivity} missing Art.29"
                )

    def test_sensitivity_below_3_does_not_trigger_art_51(self):
        for td in list_types():
            if td.sensitivity < 3:
                assert "PIPL Art.51" not in td.pipl_articles, (
                    f"{td.lang}/{td.name} sens={td.sensitivity} should NOT have Art.51"
                )


class TestSensitivePITypesCoverage:
    def test_pipl_sensitive_types_have_art_55(self):
        # PIPL Art.55: impact assessment required for sensitive PI types
        # (medical, financial, religion, political, sexual_orientation,
        # criminal_record, biometric).
        for td in list_types():
            if td.name in _PIPL_SENSITIVE_TYPES:
                assert "PIPL Art.55" in td.pipl_articles, (
                    f"{td.lang}/{td.name} is sensitive PI but missing Art.55"
                )

    def test_non_sensitive_types_no_art_55_at_typedef_level(self):
        # Art.55 from typedef should only flag truly sensitive PI types.
        # The cardinality rule (≥3 entities → Art.55) lives in assess_risk.
        for td in list_types():
            if td.name not in _PIPL_SENSITIVE_TYPES and "PIPL Art.55" in td.pipl_articles:
                raise AssertionError(
                    f"{td.lang}/{td.name} has Art.55 but isn't in _PIPL_SENSITIVE_TYPES"
                )


class TestGDPRSpecialCategory:
    def test_gdpr_special_category_set_on_art9_types(self):
        # GDPR Art.9 special categories: health, race/ethnicity, religion,
        # political opinions, sexual orientation, biometric, criminal record.
        # Note: financial is NOT GDPR Art.9 special category.
        gdpr_art9 = {
            "medical",
            "biometric",
            "ethnicity",
            "religion",
            "political",
            "sexual_orientation",
            "criminal_record",
        }
        for td in list_types():
            if td.name in gdpr_art9 and td.lang in ("zh", "en"):
                assert td.gdpr_special_category is True, (
                    f"{td.lang}/{td.name} should be GDPR Art.9 special category"
                )

    def test_credentials_not_gdpr_special_category(self):
        for td in list_types():
            if td.name in _CREDENTIAL_TYPES:
                assert td.gdpr_special_category is False, (
                    f"{td.lang}/{td.name} is a credential, not personal data — "
                    f"gdpr_special_category should be False"
                )


class TestHIPAACategories:
    def test_hipaa_categories_are_valid_safe_harbor_values(self):
        for td in list_types():
            if td.hipaa_phi_category is not None:
                assert td.hipaa_phi_category in _HIPAA_SAFE_HARBOR_CATEGORIES, (
                    f"{td.lang}/{td.name} hipaa_phi_category={td.hipaa_phi_category!r} "
                    f"not in HIPAA Safe Harbor 18 set"
                )

    def test_credentials_no_hipaa_category(self):
        for td in list_types():
            if td.name in _CREDENTIAL_TYPES:
                assert td.hipaa_phi_category is None, (
                    f"{td.lang}/{td.name} is a credential — no HIPAA PHI category"
                )

    def test_key_hipaa_categories_covered(self):
        # Sanity check: the most important HIPAA categories must have at
        # least one type mapping to them.
        all_categories = {td.hipaa_phi_category for td in list_types()
                          if td.hipaa_phi_category}
        for required in ("names", "phone_numbers", "ssn", "medical_record",
                         "email_addresses", "geographic"):
            assert required in all_categories, (
                f"No type maps to HIPAA category {required!r}"
            )


class TestDefaults:
    def test_typedef_default_compliance_fields_are_empty(self):
        # A typedef constructed with only the required positional fields
        # must default to no-compliance metadata. Adding new types without
        # explicit metadata should fail later invariants, not silently
        # inherit from a previous type.
        td = PIITypeDef(name="test_type_xyz", lang="zh", format="dummy")
        assert td.pipl_articles == ()
        assert td.gdpr_special_category is False
        assert td.hipaa_phi_category is None
