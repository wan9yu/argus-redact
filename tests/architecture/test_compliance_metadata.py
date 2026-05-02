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
from argus_redact.specs._compliance import (
    GDPR_SPECIAL_CATEGORY,
    HIPAA_SAFE_HARBOR_CATEGORIES,
    PIPL_SENSITIVE_PI,
)
from argus_redact.specs.registry import PIITypeDef, list_types

# Test imports the central sets rather than re-listing them — that way the
# test verifies the typedef respects the rule, not a parallel literal that
# could drift from the source of truth.
_PIPL_SENSITIVE_TYPES = PIPL_SENSITIVE_PI

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
    def test_art_55_iff_sensitive_pi_type(self):
        # Art.55 (impact assessment) on a typedef must align exactly with
        # PIPL_SENSITIVE_PI. The cardinality rule (≥3 entities → Art.55)
        # is enforced separately by assess_risk(), not at the typedef level.
        for td in list_types():
            has_art_55 = "PIPL Art.55" in td.pipl_articles
            should_have = td.name in _PIPL_SENSITIVE_TYPES
            assert has_art_55 == should_have, (
                f"{td.lang}/{td.name}: Art.55 present={has_art_55} "
                f"but should be {should_have} (sensitive PI: {should_have})"
            )


class TestGDPRSpecialCategory:
    def test_gdpr_special_category_set_on_art9_types(self):
        # Verify each typedef respects the central GDPR_SPECIAL_CATEGORY set
        # (financial is NOT included — PIPL treats it as sensitive PI but
        # GDPR Art.9 does not).
        for td in list_types():
            if td.name in GDPR_SPECIAL_CATEGORY and td.lang in ("zh", "en"):
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
                assert td.hipaa_phi_category in HIPAA_SAFE_HARBOR_CATEGORIES, (
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
