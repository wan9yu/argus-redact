"""Architectural guardrail: every reserved-range person name must declare aliases.

Without this test, adding a new entry to ``RESERVED_PERSON_NAMES`` (or its en
counterpart) but forgetting to add a transliteration to the ``*_ALIASES`` table
would silently degrade ``restore()`` cross-language coverage.
"""

from argus_redact.specs.fakers_en_reserved import (
    RESERVED_PERSON_NAMES_EN,
    RESERVED_PERSON_NAMES_EN_ALIASES,
)
from argus_redact.specs.fakers_zh_reserved import (
    RESERVED_PERSON_NAMES,
    RESERVED_PERSON_NAMES_ALIASES,
)


def test_every_zh_reserved_name_has_alias():
    missing = [n for n in RESERVED_PERSON_NAMES if not RESERVED_PERSON_NAMES_ALIASES.get(n)]
    assert not missing, (
        f"Reserved zh names missing pinyin aliases: {missing}. "
        f"Add an entry to RESERVED_PERSON_NAMES_ALIASES in fakers_zh_reserved.py."
    )


def test_every_en_reserved_name_has_alias():
    missing = [
        n for n in RESERVED_PERSON_NAMES_EN if not RESERVED_PERSON_NAMES_EN_ALIASES.get(n)
    ]
    assert not missing, (
        f"Reserved en names missing zh transliteration aliases: {missing}. "
        f"Add an entry to RESERVED_PERSON_NAMES_EN_ALIASES in fakers_en_reserved.py."
    )
