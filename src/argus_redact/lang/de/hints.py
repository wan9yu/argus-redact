"""German hints data — kinship "mein/meine X" prefixes + command-mode regex.

Consumed by ``argus_redact.pure.hints``. v0.5.6 minimum-viable list.
"""

from __future__ import annotations

import re

# German kinship is detected by possessive prefix on entity.text. The exact
# possessive form depends on grammatical gender: "mein Vater" vs "meine Mutter".
KINSHIP_PREFIXES: tuple[str, ...] = (
    "meine Mutter",
    "mein Vater",
    "meine Frau",
    "mein Mann",
    "mein Sohn",
    "meine Tochter",
    "meine Kinder",
    "meine Familie",
)

# Command-mode regex — covers the typical Höflichkeitsform openers and direct
# imperatives. \bbitte\b is intentionally narrow (word boundaries) to avoid
# false positives on prose mentioning "bitte" mid-sentence.
COMMAND_PATTERN: re.Pattern = re.compile(
    r"\b(?:können|könnten|würden)\s+Sie\b"
    r"|\bbitte\b"
    r"|\bkontaktieren\s+Sie\s+mich\b"
    r"|\bsagen\s+Sie\s+mir\b",
    re.IGNORECASE,
)
