"""Frozen per-type compliance decision table — the correctness oracle.

This module carries **double duty**:

1. **Correctness oracle.** For every registered PII type it records the OLD
   PIPL/GDPR/HIPAA classification (a frozen literal snapshot of the live
   registry at the v0.8.10 baseline) next to the PROPOSED NEW classification.
   Freezing the OLD column keeps the before/after delta a true historical
   record: once the value-flip lands, ``old`` stays fixed while the live code
   moves to match ``new``. Later compliance work
   asserts that the live ``assess_risk`` output equals the ``new`` column here —
   a green suite alone does not prove the law is stated correctly; equality with
   this reviewed table does.

2. **Transparency artifact consistency.** The published, human-readable
   ``docs/compliance-mappings.md`` is rendered by
   ``argus_redact.specs.gen_compliance_mappings`` from the live registry; this
   oracle imports the same verbatim statute citations from that generator (one
   direction only: tests → specs) and pairs each mapping with a one-line
   rationale, so the published doc and this table cite from a single source.

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
    _FINANCIAL_ACCOUNTS_EXTRA,
    _GENERAL_CLAUSE_EXTRA,
    _IDENTITY_CREDENTIALS,
    HIPAA_SAFE_HARBOR_CATEGORIES,
    PIPL_ART_13,
    PIPL_ART_28,
    PIPL_ART_29,
    PIPL_ART_51,
    PIPL_ART_55,
    PIPL_ART_56,
    PIPL_SORT_ORDER,
)
from argus_redact.specs.gen_compliance_mappings import (
    _DOWNGRADE_CITE,
    _MEMBER_BASIS,
    _NON_NATURAL_PERSON,
    GDPR_ART9_CITE,
    GDPR_ART10_CITE,
    PIPL_ART28_BASIS,
    hipaa_cite,
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

# The three sensitive-PI addition constants — ``_IDENTITY_CREDENTIALS`` (national-ID
# / identity-credential numbers, PIPL Art.28 ¶1 harm clause), ``_FINANCIAL_ACCOUNTS_EXTRA``
# (provident-fund accounts), and ``_GENERAL_CLAUSE_EXTRA`` (ethnicity, via the Art.28
# general clause) — now live in the runtime rule book (``specs/_compliance.py``) as the
# live SSOT for ``PIPL_SENSITIVE_PI``. The oracle IMPORTS them (tests → specs, one
# direction) so ``SENSITIVE_PI_NEW`` below and the live membership derive from a single
# source with no 32-name hand-copy to drift.

# Frozen snapshot of the live ``PIPL_SENSITIVE_PI`` base (the 9 members as they are
# at the v0.8.10 baseline). This is a BARE frozen constant, deliberately NOT a
# ``LEGACY == live PIPL_SENSITIVE_PI`` self-test: the value-flip EXPANDS the live
# set, so such an assertion would go RED the moment the flip lands — re-creating the
# exact live-coupling this freeze exists to break. The "newly-member" delta
# (``SENSITIVE_PI_NEW - PIPL_SENSITIVE_PI_LEGACY``) is therefore computed against
# this fixed base, not the live set.
PIPL_SENSITIVE_PI_LEGACY: frozenset[str] = frozenset(
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

SENSITIVE_PI_NEW: frozenset[str] = (
    PIPL_SENSITIVE_PI_LEGACY
    | _IDENTITY_CREDENTIALS
    | _FINANCIAL_ACCOUNTS_EXTRA
    | _GENERAL_CLAUSE_EXTRA
)

# GDPR Art.9 special categories under the new rule: criminal_record LEAVES Art.9
# and moves to the new Art.10 dimension; everything else is unchanged. Pinned as an
# INDEPENDENT frozen literal (not derived live) so the NEW column is a fixed reviewed
# target — a value-flip that silently added or dropped a GDPR-special type cannot
# follow it. The literal includes nhs_number, a per-typedef override (a health
# identifier that is GDPR Art.9 health data per Recital 35) — the same fragile
# hand-seed pattern the HIPAA guard covers. ``test_gdpr_special_new_pin_matches_derived``
# proves this pin still equals what today's registry derives.
GDPR_SPECIAL_NEW: frozenset[str] = frozenset(
    {
        "biometric",
        "ethnicity",
        "medical",
        "nhs_number",
        "political",
        "religion",
        "sexual_orientation",
    }
)

# GDPR Art.10 — personal data on criminal convictions and offences (parallel to,
# and mutually exclusive with, Art.9 special categories).
GDPR_ART10_NEW: frozenset[str] = frozenset({"criminal_record"})

# HIPAA Safe Harbor mapping under the new rule. Delta from the live map: the
# free-text ``financial`` type drops its ``account_numbers`` mapping (a salary or
# credit-score mention is not an account number). Structured account types
# (bank_card / credit_card) keep it. passport→certificate_number is retained
# (verified: HIPAA identifier (K)). itin gains other_unique_identifier (letter R):
# an ITIN is a unique personal identifier but not an SSN, so declining it would leave
# it in "de-identified" output (a real Safe-Harbor hole).
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
    "itin": "other_unique_identifier",  # unique personal id but not an SSN → HIPAA (R)
    "nhs_number": "medical_record",  # set explicitly on the uk typedef
}

# HIPAA categories carried on a per-typedef override (set on the intl typedef, NOT
# the central ``_HIPAA_MAP``). Pinned so the hand-built ``HIPAA_NEW`` dict above can be
# checked to still carry them — the same fragile hand-seed pattern as the GDPR pin.
# ``test_hipaa_typedef_overrides_are_pinned`` is its guard.
_HIPAA_TYPEDEF_OVERRIDES: dict[str, str] = {"nhs_number": "medical_record"}


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
    if name not in (SENSITIVE_PI_NEW - PIPL_SENSITIVE_PI_LEGACY):
        return ""
    base = sensitivity / 4.0
    old_amp = (name in PIPL_SENSITIVE_PI_LEGACY) or (name in _SELF_REF_EXTRA)
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
    # OLD — frozen literal snapshot of the live registry at the v0.8.10 baseline.
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


# ─────────────────────────────────────────────────────────────────────────────
# FROZEN OLD columns — the historical before-state, keyed by (lang, name).
#
# Each value is ``(old_pipl_articles, old_gdpr_special, old_hipaa)``; ``old_gdpr_art10``
# is uniformly False (the dimension did not exist). Captured mechanically from the
# live registry at the v0.8.10 baseline and pasted here as literals so ``old`` stays
# fixed once the value-flip lands — otherwise ``old`` would read live and track
# ``new``, emptying the before/after delta the gateway notice is generated from.
# DO NOT hand-edit: regenerate from the pre-flip registry if the type set changes.
# ─────────────────────────────────────────────────────────────────────────────
# The three distinct OLD PIPL article shapes (pre-flip): ordinary PII, sensitivity≥3,
# and sensitive-PI member. Referencing the canonical article constants keeps the frozen
# record about WHICH articles applied, not their spelling.
_OLD_PIPL_ORDINARY = (PIPL_ART_13, PIPL_ART_28, PIPL_ART_56)
_OLD_PIPL_S3 = (PIPL_ART_13, PIPL_ART_28, PIPL_ART_51, PIPL_ART_29, PIPL_ART_56)
_OLD_PIPL_MEMBER = (
    PIPL_ART_13,
    PIPL_ART_28,
    PIPL_ART_51,
    PIPL_ART_29,
    PIPL_ART_55,
    PIPL_ART_56,
)
_OLD_COLUMNS: dict[tuple[str, str], tuple[tuple[str, ...], bool, str | None]] = {
    ("zh", "phone"): (_OLD_PIPL_S3, False, "phone_numbers"),
    ("zh", "phone_landline"): (_OLD_PIPL_S3, False, "phone_numbers"),
    ("zh", "id_number"): (_OLD_PIPL_S3, False, None),
    ("zh", "hk_id"): (_OLD_PIPL_S3, False, None),
    ("zh", "tw_id"): (_OLD_PIPL_S3, False, None),
    ("zh", "macau_id"): (_OLD_PIPL_S3, False, None),
    ("zh", "taiwan_arc"): (_OLD_PIPL_S3, False, None),
    ("zh", "eep"): (_OLD_PIPL_S3, False, None),
    ("zh", "hrp"): (_OLD_PIPL_S3, False, None),
    ("zh", "housing_fund"): (_OLD_PIPL_S3, False, None),
    ("zh", "bank_card"): (_OLD_PIPL_MEMBER, False, "account_numbers"),
    ("zh", "passport"): (_OLD_PIPL_S3, False, "certificate_number"),
    ("zh", "license_plate"): (_OLD_PIPL_ORDINARY, False, "vehicle_identifier"),
    ("zh", "address"): (_OLD_PIPL_ORDINARY, False, "geographic"),
    ("zh", "credit_code"): (_OLD_PIPL_S3, False, None),
    ("zh", "qq"): (_OLD_PIPL_ORDINARY, False, None),
    ("zh", "wechat"): (_OLD_PIPL_ORDINARY, False, None),
    ("zh", "date_of_birth"): (_OLD_PIPL_ORDINARY, False, "dates"),
    ("zh", "military_id"): (_OLD_PIPL_S3, False, None),
    ("zh", "social_security"): (_OLD_PIPL_S3, False, "ssn"),
    ("zh", "job_title"): (_OLD_PIPL_ORDINARY, False, None),
    ("zh", "organization"): (_OLD_PIPL_ORDINARY, False, None),
    ("zh", "school"): (_OLD_PIPL_ORDINARY, False, None),
    ("zh", "ethnicity"): (_OLD_PIPL_S3, True, None),
    ("zh", "workplace"): (_OLD_PIPL_ORDINARY, False, None),
    ("zh", "hobby"): (_OLD_PIPL_ORDINARY, False, None),
    ("zh", "criminal_record"): (_OLD_PIPL_MEMBER, True, None),
    ("zh", "financial"): (_OLD_PIPL_MEMBER, False, "account_numbers"),
    ("zh", "biometric"): (_OLD_PIPL_MEMBER, True, "biometric"),
    ("zh", "medical"): (_OLD_PIPL_MEMBER, True, "medical_record"),
    ("zh", "religion"): (_OLD_PIPL_MEMBER, True, None),
    ("zh", "political"): (_OLD_PIPL_MEMBER, True, None),
    ("zh", "sexual_orientation"): (_OLD_PIPL_MEMBER, True, None),
    ("zh", "self_reference"): (_OLD_PIPL_ORDINARY, False, None),
    ("zh", "person"): (_OLD_PIPL_S3, False, "names"),
    ("zh", "age"): (_OLD_PIPL_ORDINARY, False, None),
    ("en", "phone"): (_OLD_PIPL_ORDINARY, False, "phone_numbers"),
    ("en", "ssn"): (_OLD_PIPL_S3, False, "ssn"),
    ("en", "itin"): (_OLD_PIPL_S3, False, None),
    ("en", "credit_card"): (_OLD_PIPL_MEMBER, False, "account_numbers"),
    ("en", "address"): (_OLD_PIPL_ORDINARY, False, "geographic"),
    ("en", "person"): (_OLD_PIPL_ORDINARY, False, "names"),
    ("en", "date_of_birth"): (_OLD_PIPL_S3, False, "dates"),
    ("en", "us_passport"): (_OLD_PIPL_S3, False, "certificate_number"),
    ("en", "medical"): (_OLD_PIPL_MEMBER, True, "medical_record"),
    ("en", "financial"): (_OLD_PIPL_MEMBER, False, "account_numbers"),
    ("en", "criminal_record"): (_OLD_PIPL_MEMBER, True, None),
    ("en", "biometric"): (_OLD_PIPL_MEMBER, True, "biometric"),
    ("en", "religion"): (_OLD_PIPL_MEMBER, True, None),
    ("en", "political"): (_OLD_PIPL_MEMBER, True, None),
    ("en", "sexual_orientation"): (_OLD_PIPL_MEMBER, True, None),
    ("en", "self_reference"): (_OLD_PIPL_ORDINARY, False, None),
    ("shared", "openai_api_key"): (_OLD_PIPL_S3, False, None),
    ("shared", "anthropic_api_key"): (_OLD_PIPL_S3, False, None),
    ("shared", "aws_access_key"): (_OLD_PIPL_S3, False, None),
    ("shared", "github_token"): (_OLD_PIPL_S3, False, None),
    ("shared", "jwt"): (_OLD_PIPL_S3, False, None),
    ("shared", "ssh_private_key"): (_OLD_PIPL_S3, False, None),
    ("shared", "email"): (_OLD_PIPL_ORDINARY, False, "email_addresses"),
    ("shared", "ip_address"): (_OLD_PIPL_ORDINARY, False, "ip_address"),
    ("shared", "mac_address"): (_OLD_PIPL_ORDINARY, False, "device_identifier"),
    ("shared", "phone_landline"): (_OLD_PIPL_ORDINARY, False, "phone_numbers"),
    ("shared", "date"): (_OLD_PIPL_ORDINARY, False, "dates"),
    ("shared", "url"): (_OLD_PIPL_ORDINARY, False, "url"),
    # Newly classified (unregistered before v0.8.10 — compliance_for returned None
    # and a report showed no statute articles). The honest OLD baseline is empty:
    # no PIPL articles, not GDPR-special, no HIPAA category. The before/after delta
    # therefore reads as "newly classified" (empty → floor; +member set for iban).
    ("shared", "iban"): ((), False, None),
    ("shared", "url_token"): ((), False, None),
    ("shared", "imei"): ((), False, None),
    ("shared", "gender"): ((), False, None),
    ("de", "tax_id"): (_OLD_PIPL_S3, False, None),
    ("ja", "my_number"): (_OLD_PIPL_S3, False, None),
    ("ko", "rrn"): (_OLD_PIPL_S3, False, None),
    ("uk", "nhs_number"): (_OLD_PIPL_S3, True, "medical_record"),
    ("uk", "nino"): (_OLD_PIPL_S3, False, None),
    ("uk", "postcode"): (_OLD_PIPL_ORDINARY, False, None),
    ("in", "aadhaar"): (_OLD_PIPL_S3, False, None),
    ("in", "pan"): (_OLD_PIPL_S3, False, None),
    ("br", "cpf"): (_OLD_PIPL_S3, False, None),
    ("br", "cnpj"): (_OLD_PIPL_ORDINARY, False, None),
}


def _build_decision(td) -> Decision:
    name, lang, sens = td.name, td.lang, td.sensitivity
    member = name in SENSITIVE_PI_NEW
    downgrade = ((sens >= 3) or name in _NON_NATURAL_PERSON) and not member
    old_pipl, old_gdpr_special, old_hipaa = _OLD_COLUMNS[(lang, name)]

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
        old_pipl=old_pipl,
        old_gdpr_special=old_gdpr_special,
        old_gdpr_art10=False,
        old_hipaa=old_hipaa,
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
# Consistency checker (the Step 3 oracle self-test). Pure Python — no LLM, no
# Rust build required. Run only this file:
#   python -m pytest tests/compliance/decision_table_v0810.py -p no:cacheprovider -q
# ─────────────────────────────────────────────────────────────────────────────

_REGISTERED_NAMES = {td.name for td in _TYPES}


def test_covers_all_registered_types():
    """The table has exactly one entry per registered (lang, name)."""
    registered = {(td.lang, td.name) for td in _TYPES}
    assert set(DECISION_TABLE) == registered
    assert len(DECISION_TABLE) == 78, f"expected 78 registered types, got {len(DECISION_TABLE)}"


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
    """The new membership is a superset of the frozen legacy base (never silent-
    downgrade a base member)."""
    assert PIPL_SENSITIVE_PI_LEGACY <= SENSITIVE_PI_NEW


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
    """OLD Art.9 (asserted against the FROZEN literal) → NEW Art.10."""
    for key, d in DECISION_TABLE.items():
        if d.name == "criminal_record":
            _old_pipl, old_gdpr_special, _old_hipaa = _OLD_COLUMNS[key]
            assert old_gdpr_special is True, f"{key}: frozen OLD Art.9 must be True"
            assert d.old_gdpr_special is True, f"{key}: Decision OLD Art.9 must be True"
            assert d.new_gdpr_special is False, f"{key}: criminal_record must leave Art.9"
            assert d.new_gdpr_art10 is True, f"{key}: criminal_record must enter Art.10"


def test_hipaa_deltas():
    """financial drops account_numbers; passport keeps certificate_number; itin gains
    other_unique_identifier (R); OLD asserted against the FROZEN literal; values valid."""
    for key, d in DECISION_TABLE.items():
        _old_pipl, _old_gdpr_special, old_hipaa = _OLD_COLUMNS[key]
        if d.name == "financial":
            assert old_hipaa == "account_numbers", f"{key}: frozen OLD financial HIPAA"
            assert d.new_hipaa is None, f"{key}: financial must drop its HIPAA mapping"
        if d.name in ("passport", "us_passport"):
            assert d.new_hipaa == "certificate_number", key
        if d.name == "itin":
            assert old_hipaa is None, f"{key}: frozen OLD itin had no HIPAA mapping"
            assert d.new_hipaa == "other_unique_identifier", f"{key}: itin must gain HIPAA (R)"
        if d.new_hipaa is not None:
            assert d.new_hipaa in HIPAA_SAFE_HARBOR_CATEGORIES, f"{key}: bad HIPAA {d.new_hipaa}"
            assert any(c.startswith("HIPAA Safe Harbor") for c in d.citations), key


def test_reconciled_name_pairs_agree():
    """Reconciled synonyms land on the same sensitive-PI decision."""
    for a, b in (("ssn", "social_security"), ("passport", "us_passport")):
        assert (a in SENSITIVE_PI_NEW) == (b in SENSITIVE_PI_NEW), f"{a}/{b} disagree on membership"


def test_newly_member_types_carry_a_risk_note():
    for key, d in DECISION_TABLE.items():
        newly = d.name in (SENSITIVE_PI_NEW - PIPL_SENSITIVE_PI_LEGACY)
        assert bool(d.risk_note) == newly, f"{key}: risk_note presence != newly-member status"


def test_old_columns_cover_exactly_the_registered_types():
    """The frozen OLD snapshot has one entry per registered (lang, name) — no stale
    rows, no gaps (a gap already KeyErrors at table build, this catches stale extras)."""
    assert set(_OLD_COLUMNS) == {(td.lang, td.name) for td in _TYPES}


def test_gdpr_special_new_pin_matches_derived():
    """The pinned GDPR Art.9 literal equals what today's registry derives (union of the
    category-name set AND per-typedef overrides, minus criminal_record which moves to
    Art.10). Catches a silent drift in the fragile hand-seeded special-category set.
    The ``- criminal_record`` keeps this stable across the value-flip."""
    derived = frozenset(d.name for d in _TYPES if d.gdpr_special_category) - {"criminal_record"}
    assert GDPR_SPECIAL_NEW == derived, (
        f"pin != derived; pin-only={sorted(GDPR_SPECIAL_NEW - derived)}, "
        f"derived-only={sorted(derived - GDPR_SPECIAL_NEW)}"
    )
    assert "nhs_number" in GDPR_SPECIAL_NEW, "per-typedef override nhs_number must be pinned"


def test_hipaa_typedef_overrides_are_pinned():
    """Per-typedef HIPAA overrides (nhs_number) are present in the hand-built HIPAA_NEW
    dict — guards the same fragile hand-seed pattern as the GDPR pin."""
    for name, cat in _HIPAA_TYPEDEF_OVERRIDES.items():
        assert HIPAA_NEW.get(name) == cat, (
            f"{name}: HIPAA_NEW override is {HIPAA_NEW.get(name)!r}, expected {cat!r}"
        )


def test_legal_entity_types_are_explicit_downgrades():
    """Legal-entity registries (credit_code, cnpj) are cited non-member downgrades even
    below the S≥3 gate — cnpj (s2) trips the _NON_NATURAL_PERSON path, not the sensitivity
    one, so it still renders in the cited '## Explicit downgrades' section."""
    for name in _NON_NATURAL_PERSON:
        decisions = [d for k, d in DECISION_TABLE.items() if d.name == name]
        assert decisions, f"{name}: not registered"
        for d in decisions:
            assert not d.sensitive_pi_member, f"{name}: legal-entity type must be a non-member"
            assert d.downgrade, f"{name}: legal-entity type must render as an explicit downgrade"
            assert d.name in _DOWNGRADE_CITE, f"{name}: needs a downgrade citation"


def test_matches_decision_table():
    """The value-flip gate: the LIVE registry classification equals the frozen
    NEW oracle columns for every registered type, across all four reviewed
    dimensions.

    A green suite alone does not prove the law is stated correctly; equality with
    this reviewed table does. Binding only ``new_pipl`` would leave three of the
    four reviewed dimensions unchecked — so this also binds GDPR Art.9, GDPR
    Art.10, and HIPAA, plus their mutual exclusion, so that (for example)
    criminal_record's Art.9→Art.10 move or a lingering double-membership cannot
    ship silently. No score/level assertion lives here (that shift is locked by
    the ``assess_risk`` golden vectors in ``tests/compliance/test_risk_golden.py``).
    """
    from argus_redact.specs._compliance import gdpr_art10_for, pipl_articles_for

    for td in _TYPES:
        d = DECISION_TABLE[(td.lang, td.name)]
        # PIPL — the live SSOT function AND the registered typedef field agree
        # with the frozen NEW tuple (tuple-equality; risk.rs re-sorts downstream).
        assert pipl_articles_for(td.name) == d.new_pipl, (
            f"{td.lang}/{td.name}: live PIPL {pipl_articles_for(td.name)} != oracle {d.new_pipl}"
        )
        assert td.pipl_articles == d.new_pipl, (
            f"{td.lang}/{td.name}: registered PIPL {td.pipl_articles} != oracle {d.new_pipl}"
        )
        # GDPR Art.9 special category — the registered field, so per-typedef
        # overrides (nhs_number) are bound too.
        assert td.gdpr_special_category == d.new_gdpr_special, (
            f"{td.lang}/{td.name}: GDPR Art.9 {td.gdpr_special_category} != {d.new_gdpr_special}"
        )
        # GDPR Art.10 — the live SSOT function and the registered field.
        assert gdpr_art10_for(td.name) == d.new_gdpr_art10, (
            f"{td.lang}/{td.name}: GDPR Art.10 {gdpr_art10_for(td.name)} != {d.new_gdpr_art10}"
        )
        assert td.gdpr_art10 == d.new_gdpr_art10, (
            f"{td.lang}/{td.name}: registered Art.10 {td.gdpr_art10} != {d.new_gdpr_art10}"
        )
        # HIPAA Safe Harbor — the registered field (binds per-typedef overrides).
        assert td.hipaa_phi_category == d.new_hipaa, (
            f"{td.lang}/{td.name}: HIPAA {td.hipaa_phi_category!r} != {d.new_hipaa!r}"
        )
        # Art.9 and Art.10 are mutually exclusive on the LIVE classification.
        assert not (td.gdpr_special_category and td.gdpr_art10), (
            f"{td.lang}/{td.name}: both GDPR Art.9 and Art.10 are set"
        )
