"""Indian English hints — kinship phrases + command-mode regex.

Indian English uses "my" + relative similar to en, plus a few culture-specific
kinship terms (papa/mummy/uncle/auntie used as common forms of address).
"""

from __future__ import annotations

import re

KINSHIP_PREFIXES: tuple[str, ...] = (
    "my ",
)

# Exact-match kinship terms common in Indian English.
KINSHIP: frozenset[str] = frozenset({
    "my papa",
    "my mummy",
    "my mama",
    "my didi",
    "my bhaiya",
    "my chacha",
    "my mausi",
})

COMMAND_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(
        r"\bkindly\b"
        r"|\bplease do the needful\b"
        r"|\brevert\b"
        r"|\bdo the needful\b",
        re.IGNORECASE,
    ),
)
