"""Reserved-range fakers for en PII types.

Each function takes (original_value: str, rng: random.Random) -> str and outputs
a value in an officially-reserved or convention-reserved range:
  - phone:       NANP 555-0100 to 555-0199 (FCC 47 CFR § 52.15(f)(1)(ii))
  - ssn:         999-XX-XXXX (SSA permanently excludes 9XX area numbers)
  - credit_card: 999999 BIN (unassigned in card-issuer space) + Luhn
  - person:      John Doe / Jane Roe / Richard Roe etc. (US legal placeholders)
  - address:     fixed-fictional table (1313 Mockingbird Lane, Springfield USA etc.)
"""

from __future__ import annotations

import random


RESERVED_PERSON_NAMES_EN = (
    "John Doe",
    "Jane Doe",
    "Jane Roe",
    "John Roe",
    "Richard Roe",
    "Mary Roe",
    "John Q. Public",
    "James Smith",
    "Alice Liddell",
    "Bob Loblaw",
)

# Fictional addresses from US/UK pop culture; deliberately recognizable as fake
RESERVED_ADDRESSES_EN = (
    "1313 Mockingbird Lane, Springfield, USA",
    "742 Evergreen Terrace, Springfield, USA",
    "221B Baker Street, London, UK",
    "12 Grimmauld Place, London, UK",
    "1630 Revello Drive, Sunnydale, USA",
    "31 Spooner Street, Quahog, USA",
)


def fake_phone_en_reserved(value: str, rng: random.Random) -> str:
    """Generate a (555) 555-01XX number — NANP fictional reservation."""
    last_two = rng.randint(0, 99)
    return f"(555) 555-01{last_two:02d}"


def fake_ssn_en_reserved(value: str, rng: random.Random) -> str:
    """Generate a 999-XX-XXXX SSN — SSA excludes 9XX area numbers."""
    group = rng.randint(1, 99)
    serial = rng.randint(1, 9999)
    return f"999-{group:02d}-{serial:04d}"


def fake_credit_card_en_reserved(value: str, rng: random.Random) -> str:
    """Generate a 999999-BIN 16-digit credit card with valid Luhn."""
    from argus_redact.lang.shared.patterns import luhn_check_digit

    body = "999999" + "".join(str(rng.randint(0, 9)) for _ in range(9))
    return body + str(luhn_check_digit(body))


def fake_person_en_reserved(value: str, rng: random.Random) -> str:
    """Pick a US legal placeholder name from the canonical fake-name table."""
    return rng.choice(RESERVED_PERSON_NAMES_EN)


def fake_address_en_reserved(value: str, rng: random.Random) -> str:
    """Pick a fictional pop-culture address from the fixed table."""
    return rng.choice(RESERVED_ADDRESSES_EN)
