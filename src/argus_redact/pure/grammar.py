"""English grammar normalization/de-normalization for first-person replacement."""

from __future__ import annotations

import re

SELF_REF_PRONOUNS = frozenset(
    {
        "I",
        "me",
        "my",
        "mine",
        "myself",
        "we",
        "us",
        "our",
        "ours",
        "ourselves",
    }
)

# Verb pairs: (first-person form, third-person form)
_VERB_PAIRS = [
    ("am", "is"),
    ("have", "has"),
    ("do", "does"),
    ("don't", "doesn't"),
]

# Forward: pseudonym + first-person verb → third-person verb
GRAMMAR_RULES_EN = [
    (re.compile(rf"(\b[A-Z]+-\d+) {first}\b"), rf"\1 {third}") for first, third in _VERB_PAIRS
] + [
    # Contractions: I'm → is, I've → has
    (re.compile(r"(\b[A-Z]+-\d+)'m\b"), r"\1 is"),
    (re.compile(r"(\b[A-Z]+-\d+)'ve\b"), r"\1 has"),
]

# Reverse: restored pronoun + third-person verb → first-person verb
GRAMMAR_RESTORE_EN = [(re.compile(rf"\bI {third}\b"), f"I {first}") for first, third in _VERB_PAIRS]


def normalize_grammar_en(text: str, key: dict[str, str]) -> str:
    """Fix English verb forms after first-person pronoun replacement."""
    if not any(v in SELF_REF_PRONOUNS for v in key.values()):
        return text
    for pattern, replacement in GRAMMAR_RULES_EN:
        text = pattern.sub(replacement, text)
    return text


def restore_grammar_en(text: str) -> str:
    """Reverse grammar normalization after restore."""
    for pattern, replacement in GRAMMAR_RESTORE_EN:
        text = pattern.sub(replacement, text)
    return text
