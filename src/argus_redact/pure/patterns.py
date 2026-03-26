"""match_patterns(text, patterns) -> list of PatternMatch. Pure regex matching."""

from __future__ import annotations

import re
from functools import lru_cache

from argus_redact._types import PatternMatch

# Context words IMMEDIATELY before a number that suggest it's NOT PII
_FALSE_POSITIVE_PREFIX = re.compile(
    r"(?:version|ver|v\.|order\s*#|product\s*code|serial\s*#|isbn|sku|"
    r"calculate|计算|订单号|编号|版本|序列号)\s*$",
    re.IGNORECASE,
)

# Arithmetic/code context IMMEDIATELY after a number
_FALSE_POSITIVE_SUFFIX = re.compile(
    r"^\s*[/\*\+\-=%\^](?:\s*\d)",
)

_CONTEXT_WINDOW = 15


@lru_cache(maxsize=128)
def _compile(pattern: str) -> re.Pattern:
    return re.compile(pattern)


def _looks_like_false_positive(text: str, start: int, end: int) -> bool:
    """Check surrounding context for non-PII indicators."""
    before = text[max(0, start - _CONTEXT_WINDOW) : start]
    after = text[end : end + _CONTEXT_WINDOW]
    if _FALSE_POSITIVE_PREFIX.search(before):
        return True
    if _FALSE_POSITIVE_SUFFIX.match(after):
        return True
    return False


def match_patterns(text: str, patterns: list[dict]) -> list[PatternMatch]:
    """Run all regex patterns against text, return sorted matches.

    Each pattern dict must have: type, label, pattern.
    Optional: validate (callable), check_context (bool).
    """
    if not text or not patterns:
        return []

    results: list[PatternMatch] = []

    for pat in patterns:
        regex = _compile(pat["pattern"])
        validate = pat.get("validate")
        check_context = pat.get("check_context", False)

        for m in regex.finditer(text):
            matched = m.group()
            if validate and not validate(matched):
                continue
            if check_context and _looks_like_false_positive(text, m.start(), m.end()):
                continue
            # Optional: extract a named group as the actual match
            group = pat.get("group")
            if group and m.group(group):
                matched = m.group(group)
                start = m.start(group)
                end = m.end(group)
            else:
                start = m.start()
                end = m.end()
            results.append(
                PatternMatch(
                    text=matched,
                    type=pat["type"],
                    start=start,
                    end=end,
                )
            )

    results.sort(key=lambda r: r.start)
    return results
