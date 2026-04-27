"""Brazilian Portuguese hints — kinship prefixes + command-mode regex."""

from __future__ import annotations

import re

KINSHIP_PREFIXES: tuple[str, ...] = (
    "minha mãe",
    "meu pai",
    "minha esposa",
    "meu marido",
    "meu filho",
    "minha filha",
    "minha família",
)

COMMAND_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(
        r"\bpor favor\b"
        r"|\bvocê\s+(?:pode|poderia)\b"
        r"|\bme\s+diga\b"
        r"|\bme\s+ajude\b",
        re.IGNORECASE,
    ),
)
