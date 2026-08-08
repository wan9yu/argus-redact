"""Frozen per-type compliance decision table — the correctness oracle.

This module carries **double duty**:

1. **Correctness oracle.** For every registered PII type it records the OLD
   PIPL/GDPR/HIPAA classification (snapshotted mechanically from the live
   registry) next to the PROPOSED NEW classification. Later compliance work
   asserts that the live ``assess_risk`` output equals the ``new`` column here —
   a green suite alone does not prove the law is stated correctly; equality with
   this reviewed table does.

2. **Transparency artifact source.** The published, human-readable
   ``docs/compliance-mappings.md`` is generated from / kept consistent with this
   table: every mapping is shelved next to its verbatim statute citation and a
   one-line rationale.

The classification is expressed as **data** — per-type article sets plus
membership frozensets — not imperative branches, so a future compliance-profile
layer can select or override it per jurisdiction or risk posture without
rewriting logic.

Governing principle (conservative, fail-safe default): where standards genuinely
diverge, over-flag; never silently downgrade. A high-sensitivity type left out of
the sensitive-personal-information set carries an explicit, cited downgrade line.

Nothing here changes runtime behaviour: the live code still emits the OLD column
until the separate value-flip lands. This table records both states so that flip
can be verified against a reviewed target.
"""

from __future__ import annotations

from dataclasses import dataclass

from argus_redact.specs._compliance import (
    HIPAA_SAFE_HARBOR_CATEGORIES,
    PIPL_ART_13,
    PIPL_ART_28,
    PIPL_ART_29,
    PIPL_ART_51,
    PIPL_ART_55,
    PIPL_ART_56,
    PIPL_SENSITIVE_PI,
    PIPL_SORT_ORDER,
)
from argus_redact.specs.registry import list_types

# Registration order is stable and drives the .ron generation order; snapshot it
# once so both the checker and the doc generator iterate the same sequence.
_TYPES = list_types()

# ─────────────────────────────────────────────────────────────────────────────
# PIPL article composition — DATA, not imperative appends.
#
# Resolved rule (v0.8.10): the sensitivity≥3 gate is removed. Every personal-
# information type carries the universal floor; sensitive-PI members additionally
# carry the four sensitive-PI articles. A future profile layer can substitute
# these tuples per jurisdiction.
# ─────────────────────────────────────────────────────────────────────────────

PIPL_UNIVERSAL: tuple[str, ...] = (PIPL_ART_13, PIPL_ART_51)
PIPL_MEMBER_EXTRA: tuple[str, ...] = (PIPL_ART_28, PIPL_ART_29, PIPL_ART_55, PIPL_ART_56)


def pipl_new_for(name: str) -> tuple[str, ...]:
    """PIPL articles a type triggers under the resolved rule, sorted canonically.

    Universal floor for any PII type; sensitive-PI members additionally trigger
    the four sensitive-PI articles. Sorted by ``PIPL_SORT_ORDER`` so the diff
    against live output is order-invariant.
    """
    arts = set(PIPL_UNIVERSAL)
    if name in SENSITIVE_PI_NEW:
        arts |= set(PIPL_MEMBER_EXTRA)
    return tuple(sorted(arts, key=lambda a: PIPL_SORT_ORDER[a]))


# ─────────────────────────────────────────────────────────────────────────────
# Membership frozensets (keyed BY NAME — language-independent, mirroring how the
# live rule book keys ``PIPL_SENSITIVE_PI`` and ``pipl_articles_for(name, ...)``).
# ─────────────────────────────────────────────────────────────────────────────

# National-ID / identity-credential types. Basis: PIPL Art.28 ¶1 general harm
# clause — such numbers, once leaked, enable impersonation and endanger personal
# safety (conservative over-flag). Name pairs are reconciled by listing BOTH
# registry names (ssn≡social_security, passport≡us_passport) so neither variant is missed.
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
# "financial accounts" (金融账户). housing_fund is a provident-fund ACCOUNT number.
_FINANCIAL_ACCOUNTS_EXTRA: frozenset[str] = frozenset({"housing_fund"})

# The proposed sensitive-PI membership set: the current PIPL_SENSITIVE_PI plus the
# identity-credential and financial-account additions, applying Art.28's harm-based
# test uniformly. Base members are never dropped (checker enforces the superset).
# GDPR Art.9 categories PIPL does not enumerate but the general harm clause
# captures — ethnicity carries discrimination / dignity harm on disclosure,
# consistent with how political / sexual_orientation are treated. Conservative.
_GENERAL_CLAUSE_EXTRA: frozenset[str] = frozenset({"ethnicity"})

SENSITIVE_PI_NEW: frozenset[str] = (
    PIPL_SENSITIVE_PI | _IDENTITY_CREDENTIALS | _FINANCIAL_ACCOUNTS_EXTRA | _GENERAL_CLAUSE_EXTRA
)

# GDPR Art.9 special categories under the new rule: criminal_record LEAVES Art.9
# and moves to the new Art.10 dimension; everything else is unchanged. Derived from
# the LIVE registry (union of the category-name set AND per-typedef overrides such as
# nhs_number — a health identifier that is GDPR Art.9 health data per Recital 35), so
# an override can never be silently dropped by keying only off the category names.
GDPR_SPECIAL_NEW: frozenset[str] = frozenset(d.name for d in _TYPES if d.gdpr_special_category) - {
    "criminal_record"
}

# GDPR Art.10 — personal data on criminal convictions and offences (parallel to,
# and mutually exclusive with, Art.9 special categories).
GDPR_ART10_NEW: frozenset[str] = frozenset({"criminal_record"})

# HIPAA Safe Harbor mapping under the new rule. Delta from the live map: the
# free-text ``financial`` type drops its ``account_numbers`` mapping (a salary or
# credit-score mention is not an account number). Structured account types
# (bank_card / credit_card) keep it. passport→certificate_number is retained
# (verified: HIPAA identifier (K)).
HIPAA_NEW: dict[str, str] = {
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
    "url": "url",
    "date": "dates",
    "nhs_number": "medical_record",  # set explicitly on the uk typedef
}

# ─────────────────────────────────────────────────────────────────────────────
# Verbatim statute citations (DRAFT — verified next by the statute reviewer).
# Each is a single-line paraphrase-with-source suitable for the published doc.
# ─────────────────────────────────────────────────────────────────────────────

# The PIPL basis under which a type is a sensitive-PI member, keyed by a basis tag.
PIPL_ART28_BASIS: dict[str, str] = {
    "specific_identity": (
        "PIPL Art.28 ¶1 (general harm clause) — a national-ID / identity-credential "
        "number, once leaked, enables impersonation and may endanger personal or "
        "property safety, so it is treated as sensitive personal information "
        "(conservative over-flag; cf. GB/T 35273-2020 Annex B, which listed resident-ID, "
        "passport, military-ID and social-security numbers as sensitive). GB/T 45574-2025 "
        "reads 特定身份 as status rather than ID numbers, so the basis is the harm clause, "
        "not the specific-identity category."
    ),
    "financial_account": (
        'PIPL Art.28 — "financial accounts" (金融账户) are expressly enumerated as '
        "sensitive personal information."
    ),
    "medical_health": (
        'PIPL Art.28 — "medical health" (医疗健康) is expressly enumerated as '
        "sensitive personal information."
    ),
    "biometric": (
        'PIPL Art.28 — "biometric information" (生物识别信息) is expressly '
        "enumerated as sensitive personal information."
    ),
    "religious_belief": (
        'PIPL Art.28 — "religious belief" (宗教信仰) is expressly enumerated as '
        "sensitive personal information."
    ),
    "general_clause": (
        "PIPL Art.28 — the enumerated list is non-exhaustive (“including”); "
        "the general clause (information whose leakage may infringe personal "
        "dignity or endanger personal or property safety) captures this category."
    ),
}

# Which basis governs each member's PIPL classification.
_MEMBER_BASIS: dict[str, str] = {
    # base sensitive-PI, expressly enumerated
    "medical": "medical_health",
    "biometric": "biometric",
    "religion": "religious_belief",
    "bank_card": "financial_account",
    "credit_card": "financial_account",
    "financial": "general_clause",
    "housing_fund": "financial_account",
    # base sensitive-PI, via the general clause (not in Art.28's express list,
    # but GDPR-special and safety-relevant)
    "political": "general_clause",
    "sexual_orientation": "general_clause",
    "criminal_record": "general_clause",
    "ethnicity": "general_clause",
    # identity credentials → specific identity
    "id_number": "specific_identity",
    "hk_id": "specific_identity",
    "tw_id": "specific_identity",
    "macau_id": "specific_identity",
    "taiwan_arc": "specific_identity",
    "eep": "specific_identity",
    "hrp": "specific_identity",
    "passport": "specific_identity",
    "us_passport": "specific_identity",
    "military_id": "specific_identity",
    "social_security": "specific_identity",
    "ssn": "specific_identity",
    "itin": "specific_identity",
    "tax_id": "specific_identity",
    "my_number": "specific_identity",
    "rrn": "specific_identity",
    "nino": "specific_identity",
    "aadhaar": "specific_identity",
    "pan": "specific_identity",
    "cpf": "specific_identity",
    # health identifier — the health character dominates the classification
    "nhs_number": "medical_health",
}

# Explicit downgrade citations for S≥3 types deliberately left NON-members, keyed
# by name (the rationale is language-independent). Applied only where the concrete
# (lang, name) registration has sensitivity ≥ 3.
_DOWNGRADE_CITE: dict[str, str] = {
    "phone": (
        "PIPL Art.28 (by exclusion) — a telephone number is ordinary personal "
        "information, not enumerated as sensitive; its processing still requires a "
        "lawful basis under PIPL Art.13. High sensitivity here reflects "
        "re-identification leverage in combination, not sensitive-PI status."
    ),
    "phone_landline": (
        "PIPL Art.28 (by exclusion) — a landline number is ordinary personal "
        "information, not enumerated as sensitive; processing requires a lawful "
        "basis under PIPL Art.13."
    ),
    "person": (
        "PIPL Art.28 (by exclusion) — a personal name is the paradigmatic ordinary "
        "identifier and is not classified as sensitive personal information under "
        "PIPL (contrast: it is HIPAA Safe Harbor identifier (A))."
    ),
    "date_of_birth": (
        "PIPL Art.28 (by exclusion) — a date of birth is ordinary PI / a quasi-"
        "identifier, not enumerated as sensitive (contrast: it is HIPAA Safe Harbor "
        "identifier (C))."
    ),
    "openai_api_key": (
        "PIPL Art.28 (by exclusion) — an API/machine credential falls under none of "
        "the Art.28 sensitive categories; as a machine credential it is not, as such, "
        "information about an identified natural person (Art.4 rationale), and is handled "
        "as a security secret at the highest redaction priority. The universal "
        "Art.13/Art.51 processing floor still applies."
    ),
    "anthropic_api_key": (
        "PIPL Art.28 (by exclusion) — a machine API credential is not enumerated as "
        "sensitive PI; not, as such, information about a natural person (Art.4 rationale); "
        "handled as a security secret. The universal Art.13/Art.51 floor still applies."
    ),
    "aws_access_key": (
        "PIPL Art.28 (by exclusion) — a cloud access-key identifier is not enumerated as "
        "sensitive PI; a machine credential (Art.4 rationale); handled as a security "
        "secret. The universal Art.13/Art.51 floor still applies."
    ),
    "github_token": (
        "PIPL Art.28 (by exclusion) — an access token is not enumerated as sensitive PI; "
        "a machine credential (Art.4 rationale); handled as a security secret. The "
        "universal Art.13/Art.51 floor still applies."
    ),
    "jwt": (
        "PIPL Art.28 (by exclusion) — a bearer token is not enumerated as sensitive PI; a "
        "machine credential (Art.4 rationale); handled as a security secret. (A JWT MAY "
        "carry PI in its payload; that PI is redacted by its own type, not by classifying "
        "the token as sensitive PI.) The universal Art.13/Art.51 floor still applies."
    ),
    "ssh_private_key": (
        "PIPL Art.28 (by exclusion) — a private key is not enumerated as sensitive PI; a "
        "machine credential (Art.4 rationale); handled as a security secret at the highest "
        "redaction priority. The universal Art.13/Art.51 floor still applies."
    ),
    "credit_code": (
        "PIPL Art.28 (by exclusion) — the Unified Social Credit Code identifies a legal "
        "entity/organization, not a natural person (Art.4), so it is not sensitive "
        "personal information; the universal Art.13/Art.51 processing floor still applies "
        "as for any processing record."
    ),
}

GDPR_ART9_CITE = (
    "GDPR Art.9(1) — processing of special categories of personal data (racial or "
    "ethnic origin, political opinions, religious or philosophical beliefs, "
    "trade-union membership, genetic data, biometric data for unique "
    "identification, health, sex life, or sexual orientation) is prohibited absent "
    "an Art.9(2) exception."
)

GDPR_ART10_CITE = (
    "GDPR Art.10 — personal data relating to criminal convictions and offences may "
    "be processed only under the control of official authority or where authorised "
    "by Union or Member State law providing appropriate safeguards."
)

# HIPAA Safe Harbor category → verbatim citation (45 CFR 164.514(b)(2)(i)(A)–(R)).
_HIPAA_LETTER: dict[str, tuple[str, str]] = {
    "names": ("A", "Names"),
    "geographic": ("B", "Geographic subdivisions smaller than a state"),
    "dates": ("C", "Dates (except year) directly related to an individual"),
    "phone_numbers": ("D", "Telephone numbers"),
    "fax_numbers": ("E", "Fax numbers"),
    "email_addresses": ("F", "Email addresses"),
    "ssn": ("G", "Social security numbers"),
    "medical_record": ("H", "Medical record numbers"),
    "health_plan_beneficiary": ("I", "Health plan beneficiary numbers"),
    "account_numbers": ("J", "Account numbers"),
    "certificate_number": ("K", "Certificate/license numbers"),
    "vehicle_identifier": ("L", "Vehicle identifiers and serial numbers"),
    "device_identifier": ("M", "Device identifiers and serial numbers"),
    "url": ("N", "Web URLs"),
    "ip_address": ("O", "Internet protocol addresses"),
    "biometric": ("P", "Biometric identifiers"),
    "full_face_photo": ("Q", "Full-face photographs and comparable images"),
    "other_unique_identifier": ("R", "Any other unique identifying number or code"),
}


def hipaa_cite(category: str) -> str:
    """Verbatim HIPAA Safe Harbor citation for a category."""
    letter, desc = _HIPAA_LETTER[category]
    return f"HIPAA Safe Harbor 45 CFR 164.514(b)(2)(i)({letter}) — {desc}."


# ─────────────────────────────────────────────────────────────────────────────
# Self-reference amplification delta (risk.rs). Membership feeds the self-ref
# score bonus, so newly-member types can raise the risk level. Modelled here for
# the record; the live value-flip is a later task.
# ─────────────────────────────────────────────────────────────────────────────

_SELF_REF_EXTRA = frozenset({"phone", "id_number", "bank_card"})  # mirrors risk.rs


def _level(score: float) -> str:
    if score < 0.3:
        return "low"
    if score < 0.6:
        return "medium"
    if score < 0.85:
        return "high"
    return "critical"


def _selfref_note(name: str, sensitivity: int) -> str:
    """One-line self-reference-pairing delta for a newly-member type, else ''.

    Models the minimal ``[self_reference, <type>]`` pair: base = sensitivity/4,
    plus a +0.15 bonus when the type participates in self-ref amplification
    (member OR a structural extra). Only newly-member types are annotated.
    """
    if name not in (SENSITIVE_PI_NEW - PIPL_SENSITIVE_PI):
        return ""
    base = sensitivity / 4.0
    old_amp = (name in PIPL_SENSITIVE_PI) or (name in _SELF_REF_EXTRA)
    new_amp = (name in SENSITIVE_PI_NEW) or (name in _SELF_REF_EXTRA)
    old_score = min(1.0, base + (0.15 if old_amp else 0.0))
    new_score = min(1.0, base + (0.15 if new_amp else 0.0))
    if round(old_score, 2) == round(new_score, 2):
        if name in _SELF_REF_EXTRA:
            return (
                "already amplified via the structural self-ref set; minimal "
                f"self-reference pair already scores {new_score:.2f}/"
                f"{_level(new_score)} (no numeric change)."
            )
        return (
            "now participates in self-reference amplification; minimal pair already "
            f"scores {new_score:.2f}/{_level(new_score)} (score capped, no change)."
        )
    return (
        f"self-reference pairing: score {old_score:.2f}→{new_score:.2f}, level "
        f"{_level(old_score)}→{_level(new_score)} (now matches sensitive-PI "
        "amplification)."
    )


# ─────────────────────────────────────────────────────────────────────────────
# The decision table.
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Decision:
    """OLD vs NEW compliance classification for one registered ``(lang, name)``."""

    lang: str
    name: str
    sensitivity: int
    # OLD — snapshotted mechanically from the live registry.
    old_pipl: tuple[str, ...]
    old_gdpr_special: bool
    old_gdpr_art10: bool  # always False: the dimension does not exist yet
    old_hipaa: str | None
    # NEW — proposed, computed from the membership frozensets + rule.
    new_pipl: tuple[str, ...]
    new_gdpr_special: bool
    new_gdpr_art10: bool
    new_hipaa: str | None
    # Classification + provenance.
    sensitive_pi_member: bool
    downgrade: bool  # S≥3 AND deliberately non-member → explicit cited determination
    citations: tuple[str, ...]  # verbatim one-line statute citation(s)
    rationale: str  # human one-liner
    risk_note: str  # self-reference amplification delta (newly-member types)


def _build_decision(td) -> Decision:
    name, lang, sens = td.name, td.lang, td.sensitivity
    member = name in SENSITIVE_PI_NEW
    downgrade = (sens >= 3) and not member

    new_gdpr_special = name in GDPR_SPECIAL_NEW
    new_gdpr_art10 = name in GDPR_ART10_NEW
    new_hipaa = HIPAA_NEW.get(name)

    citations: list[str] = []
    if member:
        citations.append(PIPL_ART28_BASIS[_MEMBER_BASIS[name]])
        rationale = "Sensitive personal information under PIPL Art.28."
    elif downgrade:
        citations.append(_DOWNGRADE_CITE[name])
        rationale = "High sensitivity, but not sensitive PI under PIPL — explicit downgrade."
    else:
        citations.append(
            "PIPL Art.13 — ordinary personal information; a lawful processing basis "
            "is required (universal floor)."
        )
        rationale = "Ordinary personal information (universal PIPL floor)."
    if new_gdpr_special:
        citations.append(GDPR_ART9_CITE)
    if new_gdpr_art10:
        citations.append(GDPR_ART10_CITE)
    if new_hipaa is not None:
        citations.append(hipaa_cite(new_hipaa))

    return Decision(
        lang=lang,
        name=name,
        sensitivity=sens,
        old_pipl=tuple(td.pipl_articles),
        old_gdpr_special=td.gdpr_special_category,
        old_gdpr_art10=False,
        old_hipaa=td.hipaa_phi_category,
        new_pipl=pipl_new_for(name),
        new_gdpr_special=new_gdpr_special,
        new_gdpr_art10=new_gdpr_art10,
        new_hipaa=new_hipaa,
        sensitive_pi_member=member,
        downgrade=downgrade,
        citations=tuple(citations),
        rationale=rationale,
        risk_note=_selfref_note(name, sens),
    )


# Keyed by (lang, name) — the registry's natural key. Insertion order preserved.
DECISION_TABLE: dict[tuple[str, str], Decision] = {
    (td.lang, td.name): _build_decision(td) for td in _TYPES
}


# ─────────────────────────────────────────────────────────────────────────────
# Transparency-artifact renderer. `docs/compliance-mappings.md` is generated from
# this table so the published doc and the oracle never drift.
# ─────────────────────────────────────────────────────────────────────────────

_PIPL_LEGEND: tuple[tuple[str, str], ...] = (
    (PIPL_ART_13, "a lawful basis is required to process personal information."),
    (
        PIPL_ART_28,
        "definition and handling rules for sensitive personal information "
        "(information whose leakage may infringe personal dignity or endanger "
        "personal or property safety).",
    ),
    (
        PIPL_ART_51,
        "the processor must adopt security measures (encryption, "
        "de-identification, access control) to protect personal information.",
    ),
    (PIPL_ART_29, "separate consent is required to process sensitive personal information."),
    (
        PIPL_ART_55,
        "a personal-information protection impact assessment is required "
        "before processing sensitive personal information.",
    ),
    (PIPL_ART_56, "the impact assessment and processing records must be retained."),
)

_BASIS_HEADING: dict[str, str] = {
    "specific_identity": (
        "Identity credentials — national-ID / credential numbers (PIPL Art.28 ¶1 harm clause)"
    ),
    "financial_account": "Financial accounts (PIPL Art.28)",
    "medical_health": "Health data (PIPL Art.28)",
    "biometric": "Biometric data (PIPL Art.28)",
    "religious_belief": "Religious belief (PIPL Art.28)",
    "general_clause": "Other categories via the Art.28 general clause",
}


def _pipl_short(articles: tuple[str, ...]) -> str:
    return ", ".join(a.replace("PIPL Art.", "") for a in articles) or "—"


def render_markdown() -> str:
    """Render the published, human-readable transparency artifact from the table."""
    lines: list[str] = []
    add = lines.append

    add("# Compliance mappings")
    add("")
    add(
        "For every personal-information type it detects, argus-redact records the "
        "PIPL, GDPR, and HIPAA obligations that type triggers. `assess_risk()` and "
        "the type catalog (`docs/pii-types.md`) expose this classification so a "
        "downstream data-protection workflow does not have to re-encode the rules."
    )
    add("")
    add(
        "This is a **conservative default, designed to be overridden.** Where legal "
        "standards genuinely diverge, argus-redact over-flags rather than "
        "silently downgrading; the classification is expressed as data so a future "
        "compliance-profile layer can select or adjust it per jurisdiction or risk "
        "posture. It is a transparency aid, **not legal advice**, and does not "
        "constitute a determination that any given text is or is not regulated."
    )
    add("")
    add("## How this table is produced")
    add("")
    add(
        "The mappings are derived mechanically from the type registry "
        "(`src/argus_redact/specs/`) and the central rule book "
        "(`specs/_compliance.py`), and are kept in lockstep with the oracle in "
        "`tests/compliance/decision_table_v0810.py`. Regenerate this document from "
        "that oracle; do not edit it by hand."
    )
    add("")
    add(f"Types covered: **{len(DECISION_TABLE)}**.")
    add("")

    add("## Statute legend")
    add("")
    add("**PIPL** (Personal Information Protection Law of the PRC):")
    add("")
    for art, gloss in _PIPL_LEGEND:
        add(f"- **{art}** — {gloss}")
    add("")
    add("**GDPR** (EU 2016/679):")
    add("")
    add(f"- **GDPR Art.9** — {GDPR_ART9_CITE.split('—', 1)[1].strip()}")
    add(f"- **GDPR Art.10** — {GDPR_ART10_CITE.split('—', 1)[1].strip()}")
    add("")
    add(
        "**HIPAA** Safe Harbor de-identification identifiers, 45 CFR "
        "164.514(b)(2)(i)(A)–(R). The identifier letter is shown per type below."
    )
    add("")

    add("## Per-type classification")
    add("")
    add(
        "PIPL articles are shown by number (see the legend). A type marked "
        "**sensitive** carries the sensitive-personal-information articles "
        "(28, 29, 55, 56) in addition to the universal floor (13, 51); the "
        "sections that follow give the statutory basis for each."
    )
    add("")
    header = "| Lang | Type | Sensitivity | PIPL | GDPR | HIPAA | Sensitive PI |"
    sep = "| --- | --- | --- | --- | --- | --- | --- |"
    add(header)
    add(sep)
    for (lang, name), d in DECISION_TABLE.items():
        gdpr = "Art.9" if d.new_gdpr_special else ("Art.10" if d.new_gdpr_art10 else "—")
        if d.new_hipaa is not None:
            letter, _ = _HIPAA_LETTER[d.new_hipaa]
            hipaa = f"{d.new_hipaa} ({letter})"
        else:
            hipaa = "—"
        member = "yes" if d.sensitive_pi_member else "no"
        add(
            f"| {lang} | {name} | {d.sensitivity} | {_pipl_short(d.new_pipl)} "
            f"| {gdpr} | {hipaa} | {member} |"
        )
    add("")

    add("## Why each type is treated as sensitive personal information")
    add("")
    add(
        "PIPL Art.28 enumerates sensitive categories and adds a general clause; the "
        "list below groups the sensitive-PI types by the basis under which they "
        "qualify. National-ID and identity-credential numbers are included because "
        "their leakage enables impersonation and endangers personal safety."
    )
    add("")
    for basis, heading in _BASIS_HEADING.items():
        names = sorted(
            {
                d.name
                for d in DECISION_TABLE.values()
                if d.sensitive_pi_member and _MEMBER_BASIS[d.name] == basis
            }
        )
        if not names:
            continue
        add(f"### {heading}")
        add("")
        add(f"> {PIPL_ART28_BASIS[basis]}")
        add("")
        add("Types: " + ", ".join(f"`{n}`" for n in names) + ".")
        add("")

    add("## Explicit downgrades")
    add("")
    add(
        "These types carry a high sensitivity score but are deliberately **not** "
        "classified as sensitive personal information under PIPL. Each downgrade is "
        "explicit and cited — never silent."
    )
    add("")
    seen: set[str] = set()
    for d in DECISION_TABLE.values():
        if d.downgrade and d.name not in seen:
            seen.add(d.name)
            add(f"- **`{d.name}`** — {d.citations[0]}")
    add("")

    add("## GDPR criminal-conviction data")
    add("")
    add(
        "`criminal_record` is classified under **GDPR Art.10** (criminal "
        "convictions and offences), a dimension parallel to — and mutually "
        "exclusive with — the Art.9 special categories."
    )
    add("")
    add(f"> {GDPR_ART10_CITE}")
    add("")

    add("## When not to rely on this")
    add("")
    add(
        "- It is a default classification, not a legal opinion; obtain "
        "jurisdiction-specific advice for regulated processing."
    )
    add(
        "- Coverage is limited to the types argus-redact detects; absence of a type "
        "here does not mean data is unregulated."
    )
    add(
        "- The sensitivity score reflects re-identification and harm risk in "
        "combination, and is distinct from a type's statutory sensitive-PI status "
        "(a high score does not by itself make a type sensitive PI)."
    )
    add("")
    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# Consistency checker (the Step 3 oracle self-test). Pure Python — no LLM, no
# Rust build required. Run only this file:
#   python -m pytest tests/compliance/decision_table_v0810.py -p no:cacheprovider -q
# ─────────────────────────────────────────────────────────────────────────────

_REGISTERED_NAMES = {td.name for td in _TYPES}


def test_covers_all_registered_types():
    """The table has exactly one entry per registered (lang, name)."""
    registered = {(td.lang, td.name) for td in _TYPES}
    assert set(DECISION_TABLE) == registered
    assert len(DECISION_TABLE) == 74, f"expected 74 registered types, got {len(DECISION_TABLE)}"


def test_membership_frozensets_have_no_typos():
    """Every name in every membership frozenset is a real registered type name."""
    for label, names in (
        ("SENSITIVE_PI_NEW", SENSITIVE_PI_NEW),
        ("GDPR_SPECIAL_NEW", GDPR_SPECIAL_NEW),
        ("GDPR_ART10_NEW", GDPR_ART10_NEW),
        ("HIPAA_NEW", set(HIPAA_NEW)),
        ("_IDENTITY_CREDENTIALS", _IDENTITY_CREDENTIALS),
        ("_FINANCIAL_ACCOUNTS_EXTRA", _FINANCIAL_ACCOUNTS_EXTRA),
    ):
        orphans = names - _REGISTERED_NAMES
        assert not orphans, f"{label} references unregistered type names: {sorted(orphans)}"


def test_new_pipl_equals_membership_rule():
    """Each new PIPL set is exactly the membership rule applied (catches hand-typos)."""
    for key, d in DECISION_TABLE.items():
        expected = pipl_new_for(d.name)
        assert d.new_pipl == expected, f"{key}: new_pipl {d.new_pipl} != rule {expected}"
        # Universal floor is always present.
        assert set(PIPL_UNIVERSAL) <= set(d.new_pipl), key
        # Member ⇔ the four sensitive-PI articles are present.
        has_extra = set(PIPL_MEMBER_EXTRA) <= set(d.new_pipl)
        assert has_extra == d.sensitive_pi_member, f"{key}: member/article mismatch"


def test_new_pipl_is_sorted_canonically():
    """new_pipl is ordered by PIPL_SORT_ORDER (order-invariant diff target)."""
    for key, d in DECISION_TABLE.items():
        ranks = [PIPL_SORT_ORDER[a] for a in d.new_pipl]
        assert ranks == sorted(ranks), f"{key}: PIPL articles not canonically sorted"


def test_base_sensitive_pi_is_never_dropped():
    """The new membership is a superset of the base set (never silent-downgrade a base member)."""
    assert PIPL_SENSITIVE_PI <= SENSITIVE_PI_NEW


def test_every_member_has_a_pipl_art28_citation():
    for key, d in DECISION_TABLE.items():
        if d.sensitive_pi_member:
            assert any(c.startswith("PIPL Art.28") for c in d.citations), (
                f"{key}: member lacks a PIPL Art.28 citation"
            )
            assert d.name in _MEMBER_BASIS, f"{key}: member missing a basis tag"


def test_every_downgrade_has_a_citation_and_rationale():
    """Every S≥3 non-member carries an explicit, cited downgrade line."""
    downgrades = {k for k, d in DECISION_TABLE.items() if d.downgrade}
    for key in downgrades:
        d = DECISION_TABLE[key]
        assert d.citations and d.citations[0], f"{key}: downgrade lacks a citation"
        assert d.rationale, f"{key}: downgrade lacks a rationale"
        assert d.name in _DOWNGRADE_CITE, f"{key}: no downgrade cite drafted for '{d.name}'"
    # No S≥3 type is left silently unclassified.
    for key, d in DECISION_TABLE.items():
        if d.sensitivity >= 3:
            assert d.sensitive_pi_member or d.downgrade, f"{key}: S≥3 neither member nor downgrade"


def test_gdpr_dimensions_are_consistent_and_cited():
    for key, d in DECISION_TABLE.items():
        # Art.9 and Art.10 are mutually exclusive.
        assert not (d.new_gdpr_special and d.new_gdpr_art10), f"{key}: both Art.9 and Art.10"
        if d.new_gdpr_special:
            assert any(c.startswith("GDPR Art.9") for c in d.citations), key
        if d.new_gdpr_art10:
            assert any(c.startswith("GDPR Art.10") for c in d.citations), key


def test_criminal_record_moves_from_art9_to_art10():
    for key, d in DECISION_TABLE.items():
        if d.name == "criminal_record":
            assert d.old_gdpr_special is True, f"{key}: expected OLD Art.9 True"
            assert d.new_gdpr_special is False, f"{key}: criminal_record must leave Art.9"
            assert d.new_gdpr_art10 is True, f"{key}: criminal_record must enter Art.10"


def test_hipaa_deltas():
    """financial drops account_numbers; passport keeps certificate_number; values are valid."""
    for key, d in DECISION_TABLE.items():
        if d.name == "financial":
            assert d.old_hipaa == "account_numbers", key
            assert d.new_hipaa is None, f"{key}: financial must drop its HIPAA mapping"
        if d.name in ("passport", "us_passport"):
            assert d.new_hipaa == "certificate_number", key
        if d.new_hipaa is not None:
            assert d.new_hipaa in HIPAA_SAFE_HARBOR_CATEGORIES, f"{key}: bad HIPAA {d.new_hipaa}"
            assert any(c.startswith("HIPAA Safe Harbor") for c in d.citations), key


def test_reconciled_name_pairs_agree():
    """Reconciled synonyms land on the same sensitive-PI decision."""
    for a, b in (("ssn", "social_security"), ("passport", "us_passport")):
        assert (a in SENSITIVE_PI_NEW) == (b in SENSITIVE_PI_NEW), f"{a}/{b} disagree on membership"


def test_newly_member_types_carry_a_risk_note():
    for key, d in DECISION_TABLE.items():
        newly = d.name in (SENSITIVE_PI_NEW - PIPL_SENSITIVE_PI)
        assert bool(d.risk_note) == newly, f"{key}: risk_note presence != newly-member status"
