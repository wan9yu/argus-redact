"""English PII type specifications.

Barebones registrations: each PIITypeDef has `_patterns=()` because detection
regex lives in `lang/en/patterns.py`. The registrations exist to attach
`faker_reserved` callables for the realistic redaction strategy.

Person detection is NER-only (spaCy), so en/person realistic-mode replacement
only fires when `mode="ner"` or higher; in `mode="fast"` person entities are
not detected at all (no regex/list fallback for en, unlike zh).
"""

from __future__ import annotations

from .fakers_en_reserved import (
    fake_address_en_reserved,
    fake_credit_card_en_reserved,
    fake_person_en_reserved,
    fake_phone_en_reserved,
    fake_ssn_en_reserved,
)
from .registry import PIITypeDef, register


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
        _patterns=(),
        faker_reserved=fake_phone_en_reserved,
        sensitivity=2,
        source="NANP; faker uses NANP 555-0100..0199 (FCC 47 CFR § 52.15(f)(1)(ii))",
        description="North American phone — detection in lang/en/patterns.py; realistic faker uses 555-01XX",
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
        _patterns=(),
        faker_reserved=fake_ssn_en_reserved,
        sensitivity=4,
        source="SSA SSN format; faker uses 999-XX-XXXX (SSA never assigns 9XX area)",
        description="US Social Security Number — detection in lang/en/patterns.py; realistic faker uses 999-XX",
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
        _patterns=(),
        faker_reserved=fake_credit_card_en_reserved,
        sensitivity=3,
        source="ISO/IEC 7812; faker uses 999999 BIN (unassigned globally) + Luhn",
        description="Credit card — detection in lang/en/patterns.py; realistic faker uses 999999 BIN",
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
        _patterns=(),
        faker_reserved=fake_address_en_reserved,
        sensitivity=2,
        source="US/UK address conventions; faker uses fictional pop-culture addresses",
        description="Street address — detection in lang/en/patterns.py; realistic faker uses fictional table",
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
        source="Detection requires NER (spaCy en_core_web_sm). No fast-mode list fallback. Faker uses US legal placeholder names (John Doe etc.)",
        description="Person name (en) — NER-only detection; realistic mode requires mode='ner' or names=[...] override",
    )
)
