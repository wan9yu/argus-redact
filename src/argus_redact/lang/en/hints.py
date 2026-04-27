"""English hints data — kinship "my X" prefix + command-mode regex.

Consumed by ``argus_redact.pure.hints``.
"""

from __future__ import annotations

import re

# Kinship is detected by literal "my " prefix on entity.text — kept
# permissive so any "my <noun>" hits the proximity boost.
KINSHIP_PREFIXES: tuple[str, ...] = ("my ",)

COMMAND_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(
        r"^(?:can you |could you |please |would you )"
        r"|\b(?:help me|tell me|show me|explain to me|let me know)\b"
        r"|^I (?:want to |need to |would like to )(?:know|ask|understand)",
        re.IGNORECASE,
    ),
)
