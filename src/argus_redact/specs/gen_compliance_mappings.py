"""Generate docs/compliance-mappings.md — the published statute-mapping artifact.

For every registered PII type, argus-redact records the PIPL / GDPR / HIPAA
obligations that type triggers. This module renders the human-readable
transparency doc from the LIVE type registry (`argus_redact.specs`) and the
central rule book (`specs/_compliance.py`) — so the doc auto-reflects the
runtime classification instead of a hand-maintained copy.

Run via:
    python -m argus_redact.specs.gen_compliance_mappings > docs/compliance-mappings.md
or:
    make compliance-mappings

The doc is committed; CI's `tests/architecture/test_compliance_mappings_drift.py`
fails when the registry diverges from the committed file. After changing
typedefs or compliance rules, run `make compliance-mappings` and commit.

The statute-citation strings live here (not in the test suite) so production
code owns them and the correctness oracle
(`tests/compliance/decision_table_v0810.py`) imports them back — one dependency
direction only (tests → specs), so the doc and the oracle cite from one source.
"""

from __future__ import annotations

# Spec typedefs register as a side effect of importing the argus_redact.specs
# package (its __init__ loads zh / en / shared / intl in canonical order, so
# list_types() returns every type in stable registration order) — the
# _compliance import below triggers that.
from argus_redact.specs._compliance import (
    HIPAA_SAFE_HARBOR,
    PIPL_ART_13,
    PIPL_ART_28,
    PIPL_ART_29,
    PIPL_ART_51,
    PIPL_ART_55,
    PIPL_ART_56,
    PIPL_SENSITIVE_PI,
    pipl_articles_for,
)
from argus_redact.specs.registry import list_types

# ─────────────────────────────────────────────────────────────────────────────
# Verbatim statute citations. Each is a single-line paraphrase-with-source
# suitable for the published doc. The oracle imports these back so the doc and
# the correctness table cite identically.
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
    "iban": "financial_account",
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

# Explicit downgrade citations for types deliberately left NON-members, keyed by
# name (the rationale is language-independent). Applied where the concrete
# (lang, name) registration has sensitivity ≥ 3 OR the type is a legal-entity /
# non-natural-person registry (see ``_NON_NATURAL_PERSON``), which downgrades even
# below the S≥3 gate (e.g. cnpj at sensitivity 2).
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
    "url_token": (
        "PIPL Art.28 (by exclusion) — a URL bearing a token/key/secret query parameter is "
        "not enumerated as sensitive PI; the embedded credential is a security secret "
        "handled at the highest redaction priority, not, as such, information about an "
        "identified natural person (Art.4 rationale). The universal Art.13/Art.51 floor "
        "still applies."
    ),
    "imei": (
        "PIPL Art.28 (by exclusion) — an IMEI is a mobile-device equipment identifier, not "
        "one of the Art.28 sensitive categories; high sensitivity reflects re-identification "
        "leverage in combination, not sensitive-PI status. The universal Art.13/Art.51 "
        "processing floor still applies."
    ),
    "credit_code": (
        "PIPL Art.28 (by exclusion) — the Unified Social Credit Code identifies a legal "
        "entity/organization, not a natural person (Art.4), so it is not sensitive "
        "personal information; the universal Art.13/Art.51 processing floor still applies "
        "as for any processing record."
    ),
    "cnpj": (
        "CNPJ = *Cadastro Nacional da Pessoa Jurídica* (legal-entity registry); MEI / "
        "sole-proprietor CNPJs map 1:1 to a natural person, so the universal {13,51} "
        "floor is retained"
    ),
}

# Legal-entity / non-natural-person registries. These identify an organization rather
# than a natural person (PIPL Art.4), so they are deliberate non-member downgrades even
# below the S≥3 gate. cnpj registers at sensitivity 2, so without this it would never
# render in the cited "Explicit downgrades" section (leaving a drift with the
# principles doc). credit_code (S3) already trips the sensitivity gate; listing it here
# makes the shared legal-entity basis explicit for both.
_NON_NATURAL_PERSON: frozenset[str] = frozenset({"credit_code", "cnpj"})

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
# The category → (letter, description) mapping is the SSOT in `specs/_compliance`
# (``HIPAA_SAFE_HARBOR``), imported above; this module only renders it.


def hipaa_cite(category: str) -> str:
    """Verbatim HIPAA Safe Harbor citation for a category."""
    letter, desc = HIPAA_SAFE_HARBOR[category]
    return f"HIPAA Safe Harbor 45 CFR 164.514(b)(2)(i)({letter}) — {desc}."


# ─────────────────────────────────────────────────────────────────────────────
# Transparency-artifact renderer. `docs/compliance-mappings.md` is generated from
# the LIVE registry so the published doc and the runtime classification never drift.
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


def _is_member(name: str) -> bool:
    """Live sensitive-PI membership (SSOT: ``specs/_compliance.PIPL_SENSITIVE_PI``)."""
    return name in PIPL_SENSITIVE_PI


def _is_downgrade(name: str, sensitivity: int) -> bool:
    """Whether a type is an explicit, cited non-member downgrade.

    A high-sensitivity type (S≥3) OR a legal-entity / non-natural-person
    registry (``_NON_NATURAL_PERSON``, which downgrades even below the S≥3 gate,
    e.g. cnpj at S2) that is deliberately not a sensitive-PI member. The
    ``_NON_NATURAL_PERSON`` term is load-bearing: a naive ``S≥3 and not member``
    recompute silently drops cnpj.
    """
    return ((sensitivity >= 3) or name in _NON_NATURAL_PERSON) and not _is_member(name)


def render_compliance_mappings() -> str:
    """Render the published, human-readable transparency artifact from the live registry."""
    types = list_types()
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
        "(`specs/_compliance.py`). This document is generated by "
        "`argus_redact.specs.gen_compliance_mappings` (run `make compliance-mappings`); "
        "the compliance oracle in `tests/compliance/decision_table_v0810.py` imports the "
        "same citation constants. Do not edit this file by hand."
    )
    add("")
    add(f"Types covered: **{len(types)}**.")
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
    for td in types:
        gdpr = "Art.9" if td.gdpr_special_category else ("Art.10" if td.gdpr_art10 else "—")
        if td.hipaa_phi_category is not None:
            letter, _ = HIPAA_SAFE_HARBOR[td.hipaa_phi_category]
            hipaa = f"{td.hipaa_phi_category} ({letter})"
        else:
            hipaa = "—"
        member = "yes" if _is_member(td.name) else "no"
        add(
            f"| {td.lang} | {td.name} | {td.sensitivity} | "
            f"{_pipl_short(pipl_articles_for(td.name))} "
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
            {td.name for td in types if _is_member(td.name) and _MEMBER_BASIS[td.name] == basis}
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
    for td in types:
        if _is_downgrade(td.name, td.sensitivity) and td.name not in seen:
            seen.add(td.name)
            add(f"- **`{td.name}`** — {_DOWNGRADE_CITE[td.name]}")
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


def main() -> None:
    import sys

    sys.stdout.write(render_compliance_mappings())


if __name__ == "__main__":
    main()
