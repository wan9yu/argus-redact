"""Japanese hints data — kinship vocabulary + command-mode suffixes.

Consumed by ``argus_redact.pure.hints``.
"""

from __future__ import annotations

# Exact-match kinship phrases.
KINSHIP: frozenset[str] = frozenset({
    "私の母",
    "私の父",
    "僕の母",
    "僕の父",
    "私の妻",
    "私の夫",
    "私の子",
    "私の家族",
    "私の息子",
    "私の娘",
    "母",
    "父",
    "妻",
    "夫",
})

# Japanese commands typically end with these forms — match against the
# trailing portion of the input.
COMMAND_SUFFIXES: tuple[str, ...] = (
    "してください",
    "してくれ",
    "教えて",
    "教えてください",
    "連絡してください",
    "お願いします",
)
