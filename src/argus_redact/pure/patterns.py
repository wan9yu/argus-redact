"""match_patterns(text, patterns) -> list of PatternMatch. Pure regex matching."""

import re

from argus_redact._types import PatternMatch


def match_patterns(text: str, patterns: list[dict]) -> list[PatternMatch]:
    """Run all regex patterns against text, return sorted matches.

    Each pattern dict must have: type, label, pattern.
    Optional: validate (callable), priority (int).
    """
    if not text or not patterns:
        return []

    results: list[PatternMatch] = []

    for pat in patterns:
        regex = re.compile(pat["pattern"])
        validate = pat.get("validate")

        for m in regex.finditer(text):
            matched = m.group()
            if validate and not validate(matched):
                continue
            results.append(PatternMatch(
                text=matched,
                type=pat["type"],
                start=m.start(),
                end=m.end(),
            ))

    results.sort(key=lambda r: r.start)
    return results
