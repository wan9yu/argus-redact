"""English PII type specifications.

Each register() call defines a PII type with its rich metadata (format,
checksum prose, sensitivity, examples, fakers, ...). The Layer-1 regex and
checksum validators (ssn, credit_card Luhn) live in the Rust core (SSOT);
PIITypeDef.to_patterns() derives the pattern dict(s) from there.

Person detection is NER-only (spaCy en_core_web_sm) — no fast-mode regex.
The person spec produces no core pattern; realistic-mode replacement only fires
when `mode="ner"` or higher.
"""

from __future__ import annotations

from .registry import PIITypeDef, list_types, register

# ── Direct identifiers ──

register(
    PIITypeDef(
        name="phone",
        lang="en",
        format="(NPA) NXX-XXXX or +1-NPA-NXX-XXXX",
        charset="digits + separators",
        strategy="mask",
        label="[PHONE REDACTED]",
        examples=("(415) 555-1234", "+1-415-555-1234"),
        counterexamples=("notaphone",),
        sensitivity=2,
        source="NANP; faker uses NANP 555-0100..0199 (FCC 47 CFR § 52.15(f)(1)(ii))",
        description="North American phone — realistic faker uses 555-01XX",
    )
)

register(
    PIITypeDef(
        name="ssn",
        lang="en",
        format="NNN-NN-NNNN",
        length=11,
        charset="digits + dashes",
        strategy="remove",
        label="[SSN REDACTED]",
        examples=("123-45-6789",),
        counterexamples=("000-12-3456", "666-12-3456", "999-12-3456"),
        sensitivity=4,
        source="SSA SSN format; faker uses 999-XX-XXXX (SSA never assigns 9XX area)",
        description="US Social Security Number — realistic faker uses 999-XX",
    )
)

register(
    PIITypeDef(
        name="itin",
        lang="en",
        format="NNN-NN-NNNN",
        length=11,
        charset="digits + dashes",
        strategy="remove",
        label="[ITIN REDACTED]",
        examples=("912-70-1234",),
        counterexamples=("912-45-6789", "123-45-6789"),
        sensitivity=4,
        source="IRS ITIN format (area 900-999, group ranges 50-65/70-88/90-92/94-99)",
        description="US Individual Taxpayer ID — SSN digit shape, IRS-assigned 9xx area",
    )
)

register(
    PIITypeDef(
        name="credit_card",
        lang="en",
        format="NNNN-NNNN-NNNN-NNNN (16 digits, Luhn-valid)",
        length=16,
        charset="digits + separators",
        checksum="Luhn",
        strategy="mask",
        label="[CARD REDACTED]",
        examples=("4111111111111111",),
        counterexamples=("1234567890123456",),
        sensitivity=3,
        source="ISO/IEC 7812; faker uses 999999 BIN (unassigned globally) + Luhn",
        description="Credit card — realistic faker uses 999999 BIN",
    )
)

register(
    PIITypeDef(
        name="address",
        lang="en",
        format="Street number + name + city",
        charset="alpha + digits + spaces",
        strategy="remove",
        label="[ADDRESS REDACTED]",
        examples=("1234 Main St, Anytown, USA",),
        counterexamples=("just plain text",),
        sensitivity=2,
        source="US/UK address conventions; faker uses fictional pop-culture addresses",
        description="Street address — realistic faker uses fictional table",
    )
)

register(
    PIITypeDef(
        name="person",
        lang="en",
        format="First Last / First Middle Last",
        charset="alpha + spaces",
        strategy="pseudonym",
        label="[NAME REDACTED]",
        examples=("John Smith", "Mary Johnson"),
        counterexamples=("the cat",),
        sensitivity=2,
        source=(
            "Detection requires NER (spaCy en_core_web_sm). No fast-mode list "
            "fallback. Faker uses US legal placeholder names (John Doe etc.)"
        ),
        description=(
            "Person name (en) — NER-only detection; realistic mode requires"
            " mode='ner' or names=[...] override"
        ),
    )
)

register(
    PIITypeDef(
        name="date_of_birth",
        lang="en",
        format="MM/DD/YYYY, YYYY-MM-DD, Month D YYYY, etc.",
        charset="digits + separators + month names",
        strategy="remove",
        label="[DOB REDACTED]",
        examples=("DOB: 01/15/1990", "Born on March 5, 1985"),
        counterexamples=("year 1990",),
        sensitivity=3,
        source="Common US/UK DOB formats; keyword-triggered for precision",
        description="English date of birth — keyword-triggered, multiple formats",
    )
)

register(
    PIITypeDef(
        name="us_passport",
        lang="en",
        format="Letter + 8 digits",
        length=9,
        charset="alphanumeric",
        strategy="remove",
        label="[PASSPORT REDACTED]",
        examples=("Passport: A12345678",),
        counterexamples=("just A12345678",),
        sensitivity=4,
        source="US Department of State passport format",
        description="US passport — keyword-triggered, letter + 8 digits",
    )
)


# ── Level 3 sensitive attributes (explicit keyword detection) ──

register(
    PIITypeDef(
        name="medical",
        lang="en",
        format="Free-form medical reference",
        charset="alpha + numeric",
        strategy="remove",
        label="[MEDICAL REDACTED]",
        examples=("diagnosed with diabetes", "HIV positive"),
        counterexamples=("medical school",),
        sensitivity=4,
        source="HIPAA PHI category",
        description="Medical/health information",
    )
)

register(
    PIITypeDef(
        name="financial",
        lang="en",
        format="Currency amount with financial keyword",
        charset="alpha + digits + symbols",
        strategy="remove",
        label="[FINANCIAL REDACTED]",
        examples=("salary of $75,000", "credit score 720"),
        counterexamples=("$5 coffee",),
        sensitivity=3,
        source="GLBA/financial privacy categories",
        description="Financial information (income/debt/credit/bankruptcy)",
    )
)

register(
    PIITypeDef(
        name="criminal_record",
        lang="en",
        format="Criminal-justice keyword phrase",
        charset="alpha + numeric",
        strategy="remove",
        label="[CRIMINAL REDACTED]",
        examples=("convicted of fraud", "felony record"),
        counterexamples=("criminal justice major",),
        sensitivity=4,
        source="GDPR special category / CCPA sensitive personal info",
        description="Criminal record",
    )
)

register(
    PIITypeDef(
        name="biometric",
        lang="en",
        format="Biometric-data keyword phrase",
        charset="alpha",
        strategy="remove",
        label="[BIOMETRIC REDACTED]",
        examples=("fingerprints collected", "DNA sample"),
        counterexamples=("biometric class",),
        sensitivity=4,
        source="GDPR Article 9 special category",
        description="Biometric identifier",
    )
)

register(
    PIITypeDef(
        name="religion",
        lang="en",
        format="Religious-affiliation keyword",
        charset="alpha",
        strategy="remove",
        label="[RELIGION REDACTED]",
        examples=("Catholic", "halal"),
        counterexamples=("Christian Bale",),
        sensitivity=3,
        source="GDPR Article 9 special category",
        description="Religious belief",
    )
)

register(
    PIITypeDef(
        name="political",
        lang="en",
        format="Political-affiliation keyword",
        charset="alpha",
        strategy="remove",
        label="[POLITICAL REDACTED]",
        examples=("registered Democrat", "voted for Republican"),
        counterexamples=("political science",),
        sensitivity=3,
        source="GDPR Article 9 special category",
        description="Political opinion",
    )
)

register(
    PIITypeDef(
        name="sexual_orientation",
        lang="en",
        format="Orientation keyword",
        charset="alpha",
        strategy="remove",
        label="[ORIENTATION REDACTED]",
        examples=("gay", "lesbian", "came out"),
        counterexamples=("queer studies",),
        sensitivity=4,
        source="GDPR Article 9 special category",
        description="Sexual orientation",
    )
)


# ── Self-reference (first-person pronouns + kinship) ──

register(
    PIITypeDef(
        name="self_reference",
        lang="en",
        format="First-person pronoun or my-kinship phrase",
        charset="alpha",
        strategy="keep",
        label="[SELF REDACTED]",
        examples=("my mother", "my husband", "I", "we"),
        counterexamples=("my book",),
        sensitivity=1,
        source="proximity-hint signal for L1b person scoring",
        description="First-person pronouns and kinship phrases — feeds self_reference_tier hint",
    )
)


# ── build_patterns() ──


def build_patterns() -> list[dict]:
    """Build the complete pattern list for English from registered specs.

    Drop-in replacement for what `lang/en/patterns.py` previously exposed.
    """
    patterns: list[dict] = []
    for typedef in list_types("en"):
        patterns.extend(typedef.to_patterns())
    return patterns
