"""match_patterns(text, patterns) -> list of PatternMatch. Pure regex matching.

Uses Rust core (_core.match_patterns) for regex + context check + group extraction.
Python handles validate callbacks (cannot be passed to Rust).
"""

from __future__ import annotations

import re as _re
from functools import lru_cache

from argus_redact._types import PatternMatch


@lru_cache(maxsize=128)
def _compile_pattern(pattern: str) -> _re.Pattern:
    return _re.compile(pattern)


def _match_python_patterns(
    text: str,
    patterns: list[dict],
    results: list[PatternMatch],
    near_misses: list[PatternMatch],
) -> None:
    """Match patterns that have validate callbacks (Python-only, shared by both paths)."""
    for pat in patterns:
        regex = _compile_pattern(pat["pattern"])
        validate = pat.get("validate")
        check_context = pat.get("check_context", False)

        for m in regex.finditer(text):
            matched = m.group()
            group = pat.get("group")
            start, end = m.start(), m.end()
            if group:
                try:
                    grp = m.group(group)
                    if grp:
                        matched, start, end = grp, m.start(group), m.end(group)
                except IndexError:
                    pass
            if validate and not validate(matched):
                near_misses.append(
                    PatternMatch(
                        text=matched, type=pat["type"], start=start, end=end, confidence=0.3
                    )
                )
                continue
            if check_context and _looks_like_false_positive(text, m.start(), m.end()):
                continue
            results.append(PatternMatch(text=matched, type=pat["type"], start=start, end=end))


_FALSE_POSITIVE_PREFIX = _re.compile(
    r"(?:version|ver|v\.|order\s*#|product\s*code|serial\s*#|isbn|sku|"
    r"calculate|计算|订单号|编号|版本|序列号)\s*$",
    _re.IGNORECASE,
)
_FALSE_POSITIVE_SUFFIX = _re.compile(
    r"^\s*[/\*\+\-=%\^](?:\s*\d)",
)
_CONTEXT_WINDOW = 15


def _looks_like_false_positive(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - _CONTEXT_WINDOW) : start]
    after = text[end : end + _CONTEXT_WINDOW]
    return bool(_FALSE_POSITIVE_PREFIX.search(before) or _FALSE_POSITIVE_SUFFIX.match(after))


try:
    from argus_redact._core import match_patterns as _rust_match_patterns

    def match_patterns(
        text: str, patterns: list[dict]
    ) -> tuple[list[PatternMatch], list[PatternMatch]]:
        """Run all regex patterns against text, return sorted matches."""
        if not text or not patterns:
            return [], []

        # Split patterns: those with validate stay in Python, rest go to Rust
        rust_patterns = []
        python_patterns = []
        for pat in patterns:
            if pat.get("validate"):
                python_patterns.append(pat)
            else:
                rust_patterns.append(pat)

        results = []
        near_misses = []

        # Rust handles patterns without validate
        if rust_patterns:
            for r in _rust_match_patterns(text, rust_patterns):
                results.append(PatternMatch(text=r.text, type=r.type, start=r.start, end=r.end))

        if python_patterns:
            _match_python_patterns(text, python_patterns, results, near_misses)

        results.sort(key=lambda r: r.start)
        return results, near_misses

except ImportError:

    def match_patterns(
        text: str, patterns: list[dict]
    ) -> tuple[list[PatternMatch], list[PatternMatch]]:
        """Run all regex patterns against text, return sorted matches (Python fallback)."""
        if not text or not patterns:
            return [], []

        results: list[PatternMatch] = []
        near_misses: list[PatternMatch] = []
        _match_python_patterns(text, patterns, results, near_misses)
        results.sort(key=lambda r: r.start)
        return results, near_misses
