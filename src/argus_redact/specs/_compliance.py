"""Compliance metadata helpers — single source for PIPL/GDPR/HIPAA rules.

PIITypeDef fields are populated automatically from these helpers when
`register()` runs (unless the typedef explicitly provides values). This keeps
the rule encoded once instead of duplicated across 50+ spec entries.

If you need to add or change a rule, edit the constants here. The catalog
(`docs/pii-types.md`) and `assess_risk()` will pick up the change after
re-import / re-generation.

Public exports (re-used by `pure/risk.py` and the test suite to avoid
parallel literal copies of the same sets):

- ``PIPL_ART_13`` … ``PIPL_ART_56`` — string constants for the six PIPL articles
- ``PIPL_SENSITIVE_PI`` — Art.28 sensitive PI category set
- ``GDPR_SPECIAL_CATEGORY`` — GDPR Art.9 set
"""

from __future__ import annotations

# PIPL article string constants. Centralizing them here prevents typo drift
# (e.g. "PIPL Art.13 " with trailing space) and keeps `pure/risk.py`,
# `assess_risk` callers, and tests in sync.
PIPL_ART_13 = "PIPL Art.13"  # Lawful basis for processing personal information
PIPL_ART_28 = "PIPL Art.28"  # De-identification requirement (any PII)
PIPL_ART_29 = "PIPL Art.29"  # Separate consent for sensitive PI
PIPL_ART_51 = "PIPL Art.51"  # Sensitive personal information definition
PIPL_ART_55 = "PIPL Art.55"  # Personal information protection impact assessment
PIPL_ART_56 = "PIPL Art.56"  # Record-keeping obligation for PI processors

# Canonical legal-reference order (not numerical) — used by `assess_risk()`
# to keep `pipl_articles` output stable across releases.
PIPL_SORT_ORDER: dict[str, int] = {
    PIPL_ART_13: 0,
    PIPL_ART_28: 1,
    PIPL_ART_51: 2,
    PIPL_ART_29: 3,
    PIPL_ART_55: 4,
    PIPL_ART_56: 5,
}

# HIPAA Safe Harbor 18 PHI identifiers per 45 CFR 164.514(b)(2)(i)(A)–(R).
# This set is the official standard reference. `_HIPAA_MAP` maps argus
# detector types to categories; not every category needs a detector (e.g.
# health_plan_beneficiary — argus ships no detector for it, but the category
# belongs in the standard's list). Test suites validate that typedef
# hipaa_phi_category values are IN this set; they do not require every
# category to have a mapping.
HIPAA_SAFE_HARBOR_CATEGORIES: frozenset[str] = frozenset(
    {
        "names",                    # (A) Names
        "geographic",               # (B) Geographic data smaller than state
        "dates",                    # (C) Dates (except year) related to individual
        "phone_numbers",            # (D) Telephone numbers
        "fax_numbers",              # (E) Fax numbers
        "email_addresses",          # (F) Email addresses
        "ssn",                      # (G) Social security numbers
        "medical_record",           # (H) Medical record numbers
        "health_plan_beneficiary",  # (I) Health plan beneficiary numbers
        "account_numbers",          # (J) Account numbers
        "certificate_number",       # (K) Certificate/license numbers
        "vehicle_identifier",       # (L) Vehicle identifiers and serial numbers
        "device_identifier",        # (M) Device identifiers and serial numbers
        "url",                      # (N) Web universal resource locators
        "ip_address",               # (O) Internet protocol address numbers
        "biometric",                # (P) Biometric identifiers
        "full_face_photo",          # (Q) Full-face photographs and comparable images
        "other_unique_identifier",  # (R) Any other unique identifying number/code
    }
)

# PIPL Art.28 sensitive personal information categories. Triggers Art.55
# (impact assessment) at the typedef level. Cardinality threshold (≥3
# entities) lives in `assess_risk()` rather than the typedef.
PIPL_SENSITIVE_PI = frozenset(
    {
        "medical",
        "financial",
        "religion",
        "political",
        "sexual_orientation",
        "criminal_record",
        "biometric",
    }
)

# GDPR Art.9 special categories of personal data. Note this differs from
# PIPL_SENSITIVE_PI — GDPR does not single out financial as a special
# category, while PIPL does.
GDPR_SPECIAL_CATEGORY = frozenset(
    {
        "medical",
        "biometric",
        "ethnicity",
        "religion",
        "political",
        "sexual_orientation",
        "criminal_record",
    }
)

# HIPAA Safe Harbor 18 mapping. Key is the argus-redact type name (lang-
# independent — zh.phone and en.phone share `name="phone"` and both map to
# "phone_numbers"). Types with no HIPAA equivalent map to None implicitly.
_HIPAA_MAP: dict[str, str] = {
    "person": "names",
    "phone": "phone_numbers",
    "phone_landline": "phone_numbers",
    "email": "email_addresses",
    "ssn": "ssn",
    "social_security": "ssn",
    "medical": "medical_record",
    "date_of_birth": "dates",
    "address": "geographic",
    "ip_address": "ip_address",
    "mac_address": "device_identifier",
    "biometric": "biometric",
    "us_passport": "certificate_number",
    "passport": "certificate_number",
    "license_plate": "vehicle_identifier",
    "financial": "account_numbers",
    "bank_card": "account_numbers",
    "credit_card": "account_numbers",
}


def pipl_articles_for(name: str, sensitivity: int) -> tuple[str, ...]:
    """Compute the PIPL articles a type triggers.

    Universal: Art.13 (lawful basis), Art.28 (de-identification), Art.56
    (record-keeping).
    Sensitivity ≥ 3: + Art.51 (sensitive PI definition), Art.29 (separate
    consent).
    Sensitive PI types: + Art.55 (impact assessment).
    """
    arts = [PIPL_ART_13, PIPL_ART_28]
    if sensitivity >= 3:
        arts.append(PIPL_ART_51)
        arts.append(PIPL_ART_29)
    if name in PIPL_SENSITIVE_PI:
        arts.append(PIPL_ART_55)
    arts.append(PIPL_ART_56)
    return tuple(arts)


def gdpr_special_for(name: str) -> bool:
    """Whether this type is a GDPR Art.9 special category."""
    return name in GDPR_SPECIAL_CATEGORY


def hipaa_for(name: str) -> str | None:
    """HIPAA Safe Harbor 18 category for this type, or None if not PHI."""
    return _HIPAA_MAP.get(name)
