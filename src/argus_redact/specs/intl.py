"""International PII type specifications — national / health / tax identifiers.

The Layer-1 regex patterns for these locales ship in the Rust core
(`data/{de,ja,ko,uk,in,br}.ron`, the SSOT), so the values were already DETECTED
and REDACTED. But the compliance registry only covered zh/en/shared, so
``report=True`` understated them: default sensitivity 2 and no PIPL/GDPR/HIPAA
classification. These defs add the risk + compliance metadata only — they do NOT
define patterns (``to_patterns()`` derives those from the core) and do NOT change
redaction: ``strategy="remove"`` mirrors the Rust ``default_strategy`` fallback for
these types, and the prefix/label fall to the same ``name.upper()[:4]`` / ``[name]``
fallbacks both runtimes already use, so the typeinfo drift guard stays in lockstep.

Sensitivity follows the established convention (cf. en.py): a national identity
number is 4 (critical, like en ``ssn`` / zh ``id_number``), a tax/financial
identifier is 3 (high), a coarse geographic identifier is 2 (medium). PIPL articles
auto-derive from sensitivity; GDPR Art.9 special-category and HIPAA apply only to
the one health identifier here (``nhs_number``) — national/tax IDs are not HIPAA PHI
(matching zh ``id_number`` → HIPAA None).
"""

from __future__ import annotations

from .registry import PIITypeDef, register

# ── Germany (de) ──
register(
    PIITypeDef(
        name="tax_id",
        lang="de",
        format="11 digits (Steuerliche Identifikationsnummer)",
        charset="digits",
        strategy="remove",
        label="[Steuer-ID]",
        sensitivity=3,
        source="Bundeszentralamt für Steuern — Steuerliche Identifikationsnummer",
        description="German national tax identification number (11 digits)",
    )
)

# ── Japan (ja) ──
register(
    PIITypeDef(
        name="my_number",
        lang="ja",
        format="12 digits (個人番号 / My Number)",
        charset="digits",
        strategy="remove",
        label="[マイナンバー]",
        sensitivity=4,
        source="Japan My Number (Individual Number) Act",
        description="Japanese national identification number (My Number, 12 digits)",
    )
)

# ── Korea (ko) ──
register(
    PIITypeDef(
        name="rrn",
        lang="ko",
        format="YYMMDD-NXXXXXX (13 digits)",
        charset="digits",
        strategy="remove",
        label="[주민등록번호]",
        sensitivity=4,
        source="Korea Resident Registration Number (주민등록번호)",
        description="Korean resident registration number — national ID encoding DOB + sex",
    )
)

# ── United Kingdom (uk) ──
register(
    PIITypeDef(
        name="nhs_number",
        lang="uk",
        format="3-3-4 digits (10, MOD11 checksum)",
        charset="digits",
        strategy="remove",
        label="[NHS number]",
        sensitivity=4,
        # Health identifier → GDPR Art.9 special category + HIPAA PHI. Set
        # explicitly because the name-derived rule book only flags generic
        # categories (medical/biometric/…), not this specific identifier.
        gdpr_special_category=True,
        hipaa_phi_category="medical_record",
        source="NHS Digital — NHS Number (patient health identifier)",
        description="UK National Health Service number (health identifier)",
    )
)
register(
    PIITypeDef(
        name="nino",
        lang="uk",
        format="AA NN NN NN A (2 letters, 6 digits, 1 letter)",
        charset="alnum",
        strategy="remove",
        label="[NINO]",
        sensitivity=3,
        source="HMRC — National Insurance Number",
        description="UK National Insurance number (tax / benefits identifier)",
    )
)
register(
    PIITypeDef(
        name="postcode",
        lang="uk",
        format="outward + inward code (e.g. SW1A 1AA)",
        charset="alnum",
        strategy="remove",
        label="[postcode]",
        sensitivity=2,
        source="Royal Mail — UK postcode",
        description="UK postcode (geographic identifier)",
    )
)

# ── India (in) ──
register(
    PIITypeDef(
        name="aadhaar",
        lang="in",
        format="4-4-4 digits (12, Verhoeff checksum)",
        charset="digits",
        strategy="remove",
        label="[Aadhaar]",
        sensitivity=4,
        source="UIDAI — Aadhaar number",
        description="Indian Aadhaar national identification number (12 digits)",
    )
)
register(
    PIITypeDef(
        name="pan",
        lang="in",
        format="AAAAA9999A (5 letters, 4 digits, 1 letter)",
        charset="alnum",
        strategy="remove",
        label="[PAN]",
        sensitivity=3,
        source="Income Tax Department — Permanent Account Number",
        description="Indian Permanent Account Number (tax identifier)",
    )
)

# ── Brazil (br) ──
register(
    PIITypeDef(
        name="cpf",
        lang="br",
        format="NNN.NNN.NNN-NN (11 digits, check digits)",
        charset="digits",
        strategy="remove",
        label="[CPF]",
        sensitivity=4,
        source="Receita Federal — Cadastro de Pessoas Físicas",
        description="Brazilian individual taxpayer registry — de facto national ID (11 digits)",
    )
)
register(
    PIITypeDef(
        name="cnpj",
        lang="br",
        format="NN.NNN.NNN/NNNN-NN (14 digits, check digits)",
        charset="digits",
        strategy="remove",
        label="[CNPJ]",
        sensitivity=2,
        source="Receita Federal — Cadastro Nacional da Pessoa Jurídica",
        description="Brazilian company taxpayer registry (legal-entity identifier)",
    )
)
