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

from argus_redact.specs._fakers_util import rand_digits


RESERVED_PERSON_NAMES_EN = (
    "John Doe",
    "Jane Doe",
    "Jane Roe",
    "John Roe",
    "Richard Roe",
    "Mary Roe",
    "John Q. Public",
    "Alice Liddell",
    # v0.6.1: "James Smith" + "Bob Loblaw" removed (statistically common real
    # US names — would alias the very PII they're meant to redact). Backfilled
    # with two more legal-placeholder Doe/Roe combinations to keep pool ≥ 10.
    "Pat Roe",
    "Sandy Doe",
)

# v0.5.8: zh transliterations the LLM might emit when it rephrases en fakes
# into Chinese script. `restore()` matches both the canonical fake and its
# aliases back to the original.
RESERVED_PERSON_NAMES_EN_ALIASES: dict[str, list[str]] = {
    "John Doe": ["约翰·多伊", "约翰多伊"],
    "Jane Doe": ["简·多伊", "简多伊"],
    "Jane Roe": ["简·罗", "简罗"],
    "John Roe": ["约翰·罗", "约翰罗"],
    "Richard Roe": ["理查德·罗", "理查德罗"],
    "Mary Roe": ["玛丽·罗", "玛丽罗"],
    "John Q. Public": ["约翰·Q·普布利克"],
    "Alice Liddell": ["爱丽丝·利德尔", "爱丽丝利德尔"],
    "Pat Roe": ["帕特·罗", "帕特罗"],
    "Sandy Doe": ["桑迪·多伊", "桑迪多伊"],
}

# Fictional addresses from US/UK pop culture; deliberately recognizable as fake
RESERVED_ADDRESSES_EN = (
    "1313 Mockingbird Lane, Springfield, USA",
    "742 Evergreen Terrace, Springfield, USA",
    "221B Baker Street, London, UK",
    "12 Grimmauld Place, London, UK",
    "1630 Revello Drive, Sunnydale, USA",
    "31 Spooner Street, Quahog, USA",
)

# v0.5.10: zh transliterations the LLM might emit when it rephrases en fake
# addresses into Chinese script. `restore()` matches both forms.
RESERVED_ADDRESSES_EN_ALIASES: dict[str, list[str]] = {
    "1313 Mockingbird Lane, Springfield, USA": ["美国斯普林菲尔德嘲鸫巷1313号"],
    "742 Evergreen Terrace, Springfield, USA": ["美国斯普林菲尔德常青露台742号"],
    "221B Baker Street, London, UK": ["英国伦敦贝克街221B号"],
    "12 Grimmauld Place, London, UK": ["英国伦敦格里莫广场12号"],
    "1630 Revello Drive, Sunnydale, USA": ["美国阳光镇雷维洛大道1630号"],
    "31 Spooner Street, Quahog, USA": ["美国奎霍格斯普纳街31号"],
}


def fake_phone_en_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate a (555) 555-01XX number — NANP fictional reservation."""
    last_two = rng.randint(0, 99)
    return f"(555) 555-01{last_two:02d}", []


def fake_ssn_en_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate a 999-XX-XXXX SSN — SSA excludes 9XX area numbers."""
    group = rng.randint(1, 99)
    serial = rng.randint(1, 9999)
    return f"999-{group:02d}-{serial:04d}", []


def fake_credit_card_en_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate a 999999-BIN 16-digit credit card with valid Luhn."""
    from argus_redact.lang.shared.patterns import luhn_check_digit

    body = "999999" + rand_digits(rng, 9)
    return body + str(luhn_check_digit(body)), []


def fake_person_en_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Pick a US legal placeholder name; emit zh transliteration aliases."""
    fake = rng.choice(RESERVED_PERSON_NAMES_EN)
    return fake, list(RESERVED_PERSON_NAMES_EN_ALIASES.get(fake, []))


def fake_address_en_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Pick a fictional pop-culture address; emit zh transliteration aliases."""
    fake = rng.choice(RESERVED_ADDRESSES_EN)
    return fake, list(RESERVED_ADDRESSES_EN_ALIASES.get(fake, []))
