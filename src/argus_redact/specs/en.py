"""English PII type specifications.

Each PIITypeDef carries its own `_patterns=(...)` regex tuple — the spec is the
single source of truth for English detection. `lang/en/patterns.py` is a thin
wrapper exposing ``PATTERNS = build_patterns()``.

Validators live here (the canonical owner) so `lang/en/patterns.py` can stay a
thin re-export without forming an import cycle.

Person detection is NER-only (spaCy en_core_web_sm) — no fast-mode regex.
The person spec keeps `_patterns=()`; realistic-mode replacement only fires
when `mode="ner"` or higher.
"""

from __future__ import annotations

from argus_redact.lang.shared.patterns import validate_luhn as _validate_luhn

from .fakers_en_reserved import (
    fake_address_en_reserved,
    fake_credit_card_en_reserved,
    fake_person_en_reserved,
    fake_phone_en_reserved,
    fake_ssn_en_reserved,
)
from .registry import PIITypeDef, list_types, register


def _validate_ssn(value: str) -> bool:
    """SSN validation per SSA rules: reject invalid area codes."""
    digits = value.replace("-", "").replace(" ", "")
    if len(digits) != 9 or not digits.isdigit():
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area == "000" or group == "00" or serial == "0000":
        return False
    if area == "666" or int(area) >= 900:
        return False
    return True


def _validate_credit_card_luhn(value: str) -> bool:
    """Luhn checksum for credit card with optional separators."""
    digits_only = value.replace("-", "").replace(" ", "")
    if not digits_only.isdigit():
        return False
    return _validate_luhn(digits_only)


_MONTHS = (
    r"(?:January|February|March|April|May|June"
    r"|July|August|September|October|November|December"
    r"|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
)


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
        _patterns=(
            {
                "type": "phone",
                "label": "[PHONE REDACTED]",
                "pattern": (
                    r"(?<!\d)(?:\+1[-.\s]?)?"
                    r"\(?\d{3}\)?[-.\s]?"
                    r"\d{3}[-.\s]?"
                    r"\d{4}"
                    r"(?!\d)"
                ),
                "description": "North American phone number",
            },
        ),
        faker_reserved=fake_phone_en_reserved,
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
        _patterns=(
            {
                "type": "ssn",
                "label": "[SSN REDACTED]",
                "pattern": r"(?<!\d)\d{3}[-\s]?\d{2}[-\s]?\d{4}(?!\d)",
                "validate": _validate_ssn,
                "check_context": True,
                "description": "US Social Security Number (with optional spaces/dashes)",
            },
        ),
        faker_reserved=fake_ssn_en_reserved,
        sensitivity=4,
        source="SSA SSN format; faker uses 999-XX-XXXX (SSA never assigns 9XX area)",
        description="US Social Security Number — realistic faker uses 999-XX",
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
        _patterns=(
            {
                "type": "credit_card",
                "label": "[CARD REDACTED]",
                "pattern": (
                    r"(?<!\d)"
                    r"[3-6]\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"
                    r"(?!\d)"
                ),
                "validate": _validate_credit_card_luhn,
                "check_context": True,
                "description": "Credit card number (Luhn checksum)",
            },
        ),
        faker_reserved=fake_credit_card_en_reserved,
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
        _patterns=(
            {
                "type": "address",
                "label": "[ADDRESS REDACTED]",
                "pattern": (
                    r"\d{1,5}\s+"
                    r"(?:[A-Z][a-z]+\s+){1,3}"
                    r"(?:St(?:reet)?|Ave(?:nue)?|Rd|Road|Blvd|Boulevard|"
                    r"Dr(?:ive)?|Ln|Lane|Way|Ct|Court|Pl(?:ace)?|Cir(?:cle)?)"
                    r"(?:\s*,\s*(?:Apt|Suite|Unit|#)\s*\w+)?"
                ),
                "description": "US street address (number + street name + type)",
            },
        ),
        faker_reserved=fake_address_en_reserved,
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
        _patterns=(),
        faker_reserved=fake_person_en_reserved,
        sensitivity=2,
        source=(
            "Detection requires NER (spaCy en_core_web_sm). No fast-mode list "
            "fallback. Faker uses US legal placeholder names (John Doe etc.)"
        ),
        description="Person name (en) — NER-only detection; realistic mode requires mode='ner' or names=[...] override",
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
        _patterns=(
            {
                "type": "date_of_birth",
                "label": "[DOB REDACTED]",
                "pattern": (
                    r"(?:date\s+of\s+birth|DOB|birthdate|birthday|born(?:\s+on)?)"
                    r"\s*[:.]?\s*"
                    r"(?P<date_of_birth>"
                    # M/D/YYYY or MM/DD/YYYY
                    r"(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:19|20)\d{2}"
                    r"|"
                    # YYYY-MM-DD
                    r"(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
                    r"|"
                    # Month D, YYYY or Month D YYYY
                    rf"{_MONTHS}\s+\d{{1,2}},?\s+(?:19|20)\d{{2}}"
                    r"|"
                    # D(st/nd/rd/th) Month YYYY
                    r"\d{1,2}(?:st|nd|rd|th)?\s+"
                    rf"{_MONTHS}\s+(?:19|20)\d{{2}}"
                    r")"
                ),
                "group": "date_of_birth",
                "description": "English date of birth (keyword-triggered, multiple formats)",
            },
        ),
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
        _patterns=(
            {
                "type": "us_passport",
                "label": "[PASSPORT REDACTED]",
                "pattern": (
                    r"(?i:passport\s*(?:number|no\.?|#)?)\s*[:.]?\s*"
                    r"(?P<us_passport>[A-Za-z]\d{8})"
                    r"(?!\d)"
                ),
                "group": "us_passport",
                "description": "US passport number (keyword-triggered, letter + 8 digits)",
            },
        ),
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
        _patterns=(
            {
                "type": "medical",
                "label": "[MEDICAL REDACTED]",
                "pattern": (
                    r"(?i:(?:diagnosed with|suffering from|treated for|prescribed|"
                    r"patient has|history of))\s+"
                    r"(?P<medical>(?i:\w[\w\s]{2,30}))"
                ),
                "group": "medical",
                "description": "Medical diagnosis (keyword-triggered, preserves trigger phrase)",
            },
            {
                "type": "medical",
                "label": "[MEDICAL REDACTED]",
                "pattern": (
                    r"(?i:HIV\s*(?:positive|negative)"
                    r"|(?:\w+\s+)?(?:surgery|transplant|chemotherapy|radiation therapy)"
                    r"|(?:diabetes|cancer|tumor|leukemia|hypertension|"
                    r"depression|schizophrenia|epilepsy|tuberculosis|hepatitis|"
                    r"alzheimer|parkinson|asthma|arthritis))"
                ),
                "description": "Medical standalone (HIV/disease/surgery)",
            },
        ),
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
        _patterns=(
            {
                "type": "financial",
                "label": "[FINANCIAL REDACTED]",
                "pattern": (
                    r"(?i:(?:salary|income|wage|earnings|pay))\s*(?:of\s*)?"
                    r"(?P<financial>\$[\d,.]+)"
                ),
                "group": "financial",
                "description": "Financial amount (keyword-triggered, preserves keyword)",
            },
            {
                "type": "financial",
                "label": "[FINANCIAL REDACTED]",
                "pattern": (
                    r"(?i:(?:owes?|debt|owed|loan|mortgage)\s+\$[\d,.]+"
                    r"(?:\s+(?:in\s+)?(?:debt|loan|mortgage))?"
                    r"|credit\s+score\s+\d{3}"
                    r"|(?:net\s+worth|annual\s+income|monthly\s+salary)\s*(?:of\s*)?\$[\d,.]+"
                    r"|(?:bankrupt|bankruptcy|foreclosure|repossession))"
                ),
                "description": "Financial standalone (debt/credit score/bankruptcy)",
            },
        ),
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
        _patterns=(
            {
                "type": "criminal_record",
                "label": "[CRIMINAL REDACTED]",
                "pattern": (
                    r"(?i:(?:convicted|convicted of|found guilty|pleaded guilty)\s+\w[\w\s]{2,20}"
                    r"|sentenced\s+to\s+\d+\s+\w+"
                    r"|(?:felony|misdemeanor)\s+(?:record|charge|conviction)"
                    r"|(?:criminal record|arrest record|police record)"
                    r"|(?:on\s+parole|on\s+probation|incarcerated|imprisoned))"
                ),
                "description": "Criminal record (conviction/sentence/felony/arrest)",
            },
        ),
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
        _patterns=(
            {
                "type": "biometric",
                "label": "[BIOMETRIC REDACTED]",
                "pattern": (
                    r"(?i:(?:fingerprint|fingerprints)\s+(?:collected|scanned|recorded|stored|data)"
                    r"|facial\s+recognition"
                    r"|(?:iris|retina)\s+scan"
                    r"|(?:voice(?:print)?|palm\s+print)\s+(?:recorded|collected|data)"
                    r"|(?:DNA|genetic)\s+(?:test|sample|data|profile|analysis)"
                    r"|biometric\s+(?:data|information|identifier))"
                ),
                "description": "Biometric data (fingerprint/facial/iris/DNA/voiceprint)",
            },
        ),
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
        _patterns=(
            {
                "type": "religion",
                "label": "[RELIGION REDACTED]",
                "pattern": (
                    r"(?i:(?:Christian|Catholic|Protestant|Muslim|Jewish|Hindu|Buddhist|"
                    r"Sikh|Mormon|Atheist|Agnostic|Orthodox)"
                    r"|(?:Sunday|Friday|Saturday)\s+(?:worship|prayer|service|mass)"
                    r"|(?:baptized|baptism|communion|confession|pilgrimage|Ramadan|"
                    r"Sabbath|kosher|halal))"
                ),
                "description": "Religious belief (faith/worship/practices)",
            },
        ),
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
        _patterns=(
            {
                "type": "political",
                "label": "[POLITICAL REDACTED]",
                "pattern": (
                    r"(?i:(?:registered|affiliated)\s+(?:Democrat|Republican|"
                    r"Labour|Conservative|Liberal|Independent)"
                    r"|voted\s+(?:for\s+)?(?:Democrat|Republican|Labour|Conservative|"
                    r"Liberal|Independent|\w+)"
                    r"|(?:protest|demonstration|rally|march)\s*(?:against|for)?"
                    r"|(?:political\s+(?:affiliation|party|opinion|belief|activist)))"
                ),
                "description": "Political opinion (party/voting/protest/affiliation)",
            },
        ),
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
        _patterns=(
            {
                "type": "sexual_orientation",
                "label": "[ORIENTATION REDACTED]",
                "pattern": (
                    r"(?i:(?:homosexual|heterosexual|bisexual|asexual|pansexual)"
                    r"|\b(?:gay|lesbian|queer|LGBTQ?)\b"
                    r"|(?:came\s+out|coming\s+out))"
                ),
                "description": "Sexual orientation (explicit terms)",
            },
        ),
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
        _patterns=(
            {
                "type": "self_reference",
                "label": "[SELF REDACTED]",
                "pattern": (
                    r"\b[Mm]y\s+(?:mother|father|mom|dad|husband|wife|spouse"
                    r"|son|daughter|brother|sister|grandfather|grandmother"
                    r"|grandma|grandpa|uncle|aunt|nephew|niece"
                    r"|partner|fiancée?|child|children|kid|kids|family)\b"
                ),
                "description": "Self-reference with kinship (my mom/my husband/...)",
            },
            {
                "type": "self_reference",
                "label": "[SELF REDACTED]",
                "pattern": r"\b(?:myself|ourselves|mine|ours|our|my|me|us|we|I)\b",
                "description": "Self-reference pronoun (I/me/my/we/our/...)",
            },
        ),
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
