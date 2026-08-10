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
- ``GDPR_ART10`` — GDPR Art.10 set (criminal convictions and offences)
"""

from __future__ import annotations

# PIPL article string constants. Centralizing them here prevents typo drift
# (e.g. "PIPL Art.13 " with trailing space) and keeps `pure/risk.py`,
# `assess_risk` callers, and tests in sync.
PIPL_ART_13 = "PIPL Art.13"  # Lawful basis for processing personal information
PIPL_ART_28 = "PIPL Art.28"  # Sensitive personal information — handling rules
PIPL_ART_29 = "PIPL Art.29"  # Separate consent for sensitive PI
PIPL_ART_51 = "PIPL Art.51"  # Security-measures obligation on all PI processing
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
        "names",  # (A) Names
        "geographic",  # (B) Geographic data smaller than state
        "dates",  # (C) Dates (except year) related to individual
        "phone_numbers",  # (D) Telephone numbers
        "fax_numbers",  # (E) Fax numbers
        "email_addresses",  # (F) Email addresses
        "ssn",  # (G) Social security numbers
        "medical_record",  # (H) Medical record numbers
        "health_plan_beneficiary",  # (I) Health plan beneficiary numbers
        "account_numbers",  # (J) Account numbers
        "certificate_number",  # (K) Certificate/license numbers
        "vehicle_identifier",  # (L) Vehicle identifiers and serial numbers
        "device_identifier",  # (M) Device identifiers and serial numbers
        "url",  # (N) Web universal resource locators
        "ip_address",  # (O) Internet protocol address numbers
        "biometric",  # (P) Biometric identifiers
        "full_face_photo",  # (Q) Full-face photographs and comparable images
        "other_unique_identifier",  # (R) Any other unique identifying number/code
    }
)

# PIPL Art.28 sensitive personal information — base categories (expressly
# enumerated in Art.28 or long-standing members). The full sensitive-PI set
# below unions this base with the identity-credential, financial-account, and
# general-clause additions. Membership triggers Art.28/29/55/56 on top of the
# universal Art.13/Art.51 floor (see `pipl_articles_for`).
_PIPL_SENSITIVE_PI_BASE: frozenset[str] = frozenset(
    {
        "medical",
        "financial",
        "bank_card",
        "credit_card",
        "religion",
        "political",
        "sexual_orientation",
        "criminal_record",
        "biometric",
    }
)

# National-ID / identity-credential types. Basis: PIPL Art.28 ¶1 general harm
# clause — such numbers, once leaked, enable impersonation and may endanger
# personal or property safety (conservative over-flag). Name pairs list BOTH
# registry names (ssn≡social_security, passport≡us_passport) so neither variant
# is missed.
_IDENTITY_CREDENTIALS: frozenset[str] = frozenset(
    {
        "id_number",  # PRC resident identity card
        "hk_id",
        "tw_id",
        "macau_id",
        "taiwan_arc",  # Alien Resident Certificate (Taiwan)
        "eep",  # Exit-Entry Permit for HK/Macao travel
        "hrp",  # Home Return Permit (HK/Macao residents → mainland)
        "passport",
        "us_passport",
        "military_id",
        "social_security",  # zh 社保号
        "ssn",  # en Social Security Number
        "itin",
        "tax_id",  # de Steuer-ID
        "my_number",  # ja
        "rrn",  # ko
        "nhs_number",  # uk health identifier
        "nino",  # uk National Insurance number
        "aadhaar",  # in
        "pan",  # in tax identifier
        "cpf",  # br de-facto national ID
    }
)

# Financial-account types beyond the base set. PIPL Art.28 expressly enumerates
# "financial accounts" (金融账户). housing_fund is a provident-fund ACCOUNT number;
# iban is a bank-account identifier.
_FINANCIAL_ACCOUNTS_EXTRA: frozenset[str] = frozenset({"housing_fund", "iban"})

# GDPR Art.9 categories PIPL does not enumerate but the Art.28 general harm
# clause captures — ethnicity carries discrimination / dignity harm on
# disclosure, consistent with how political / sexual_orientation are treated.
_GENERAL_CLAUSE_EXTRA: frozenset[str] = frozenset({"ethnicity"})

# The sensitive-PI membership set: the base plus the identity-credential,
# financial-account, and general-clause additions, applying Art.28's harm-based
# test uniformly. This is the single source of truth for both the runtime
# (`pipl_articles_for`, the risk RON) and the compliance oracle, which imports
# the three addition constants from here rather than hand-copying the names.
PIPL_SENSITIVE_PI: frozenset[str] = (
    _PIPL_SENSITIVE_PI_BASE
    | _IDENTITY_CREDENTIALS
    | _FINANCIAL_ACCOUNTS_EXTRA
    | _GENERAL_CLAUSE_EXTRA
)

# GDPR Art.9 special categories of personal data. Note this differs from
# PIPL_SENSITIVE_PI — GDPR does not single out financial as a special
# category, while PIPL does. criminal_record is NOT here: it belongs to the
# parallel (and mutually exclusive) Art.10 regime below.
GDPR_SPECIAL_CATEGORY = frozenset(
    {
        "medical",
        "biometric",
        "ethnicity",
        "religion",
        "political",
        "sexual_orientation",
    }
)

# GDPR Art.10 — personal data relating to criminal convictions and offences.
# Distinct from, and mutually exclusive with, the Art.9 special categories above
# (Art.10 has its own legal regime under Art.10 / national law). criminal_record
# moves here out of Art.9, where it never belonged: Art.9 enumerates the special
# categories and Art.10 is the dedicated regime for conviction/offence data.
GDPR_ART10: frozenset[str] = frozenset({"criminal_record"})

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
    "postcode": "geographic",  # ZIP/postcode is a geographic subdivision → HIPAA (B)
    "ip_address": "ip_address",
    "mac_address": "device_identifier",
    "biometric": "biometric",
    "us_passport": "certificate_number",
    "passport": "certificate_number",
    "license_plate": "vehicle_identifier",
    "bank_card": "account_numbers",
    "credit_card": "account_numbers",
    "housing_fund": "account_numbers",  # provident-fund account number → HIPAA (J)
    "iban": "account_numbers",  # bank-account number → HIPAA (J)
    "url": "url",
    "date": "dates",
    "itin": "other_unique_identifier",  # unique personal id but not an SSN → HIPAA (R)
}


def pipl_articles_for(name: str) -> tuple[str, ...]:
    """Compute the PIPL articles a type triggers, sorted by ``PIPL_SORT_ORDER``.

    Universal floor for any personal information: Art.13 (lawful basis) and
    Art.51 (security-measures obligation on all processing).
    Sensitive-PI members (``name in PIPL_SENSITIVE_PI``) additionally trigger
    Art.28 (sensitive-PI handling), Art.29 (separate consent), Art.55 (impact
    assessment), and Art.56 (record-keeping).

    Classification is membership-driven, not score-driven.
    """
    arts = {PIPL_ART_13, PIPL_ART_51}
    if name in PIPL_SENSITIVE_PI:
        arts |= {PIPL_ART_28, PIPL_ART_29, PIPL_ART_55, PIPL_ART_56}
    return tuple(sorted(arts, key=lambda a: PIPL_SORT_ORDER[a]))


def gdpr_special_for(name: str) -> bool:
    """Whether this type is a GDPR Art.9 special category."""
    return name in GDPR_SPECIAL_CATEGORY


def gdpr_art10_for(name: str) -> bool:
    """Whether this type is GDPR Art.10 data (criminal convictions/offences)."""
    return name in GDPR_ART10


def hipaa_for(name: str) -> str | None:
    """HIPAA Safe Harbor 18 category for this type, or None if not PHI."""
    return _HIPAA_MAP.get(name)
