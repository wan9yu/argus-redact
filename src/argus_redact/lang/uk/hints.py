"""British English hints — kinship "my X" prefix + command-mode regex.

Mirrors ``lang/en/hints.py`` with British vocabulary (mum/mam/auntie etc.).
"""

from __future__ import annotations

import re

KINSHIP_PREFIXES: tuple[str, ...] = ("my ",)

COMMAND_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(
        r"\bcould you\b"
        r"|\bplease\b"
        r"|\bwould you mind\b"
        r"|\bcheers,?\s+(?:could|can|please)\b",
        re.IGNORECASE,
    ),
)
