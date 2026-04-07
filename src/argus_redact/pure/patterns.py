"""match_patterns(text, patterns) -> list of PatternMatch. Pure regex matching.

Uses Rust core (_core.match_patterns) for regex + context check + group extraction.
Python handles validate callbacks (cannot be passed to Rust).
"""

from __future__ import annotations

from argus_redact._types import PatternMatch

# Type alias for match_patterns return
MatchResult = tuple[list[PatternMatch], list[PatternMatch]]  # (entities, near_misses)

try:
    from argus_redact._core import match_patterns as _rust_match_patterns

    def match_patterns(text: str, patterns: list[dict]) -> tuple[list[PatternMatch], list[PatternMatch]]:
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
                results.append(
                    PatternMatch(text=r.text, type=r.type, start=r.start, end=r.end)
                )

        # Python handles patterns with validate (need closure calls)
        if python_patterns:
            import re
            from functools import lru_cache

            @lru_cache(maxsize=128)
            def _compile(pattern):
                return re.compile(pattern)

            for pat in python_patterns:
                regex = _compile(pat["pattern"])
                validate = pat["validate"]
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
                    if not validate(matched):
                        near_misses.append(
                            PatternMatch(text=matched, type=pat["type"], start=start, end=end, confidence=0.3)
                        )
                        continue
                    results.append(
                        PatternMatch(text=matched, type=pat["type"], start=start, end=end)
                    )

        results.sort(key=lambda r: r.start)
        return results, near_misses

except ImportError:
    # Fallback: pure Python implementation (no Rust core available)
    import re
    from functools import lru_cache

    _FALSE_POSITIVE_PREFIX = re.compile(
        r"(?:version|ver|v\.|order\s*#|product\s*code|serial\s*#|isbn|sku|"
        r"calculate|计算|订单号|编号|版本|序列号)\s*$",
        re.IGNORECASE,
    )
    _FALSE_POSITIVE_SUFFIX = re.compile(
        r"^\s*[/\*\+\-=%\^](?:\s*\d)",
    )
    _CONTEXT_WINDOW = 15

    @lru_cache(maxsize=128)
    def _compile(pattern: str) -> re.Pattern:
        return re.compile(pattern)

    def _looks_like_false_positive(text: str, start: int, end: int) -> bool:
        before = text[max(0, start - _CONTEXT_WINDOW) : start]
        after = text[end : end + _CONTEXT_WINDOW]
        if _FALSE_POSITIVE_PREFIX.search(before):
            return True
        if _FALSE_POSITIVE_SUFFIX.match(after):
            return True
        return False

    def match_patterns(text: str, patterns: list[dict]) -> tuple[list[PatternMatch], list[PatternMatch]]:
        """Run all regex patterns against text, return sorted matches (Python fallback)."""
        if not text or not patterns:
            return [], []

        results: list[PatternMatch] = []
        near_misses: list[PatternMatch] = []

        for pat in patterns:
            regex = _compile(pat["pattern"])
            validate = pat.get("validate")
            check_context = pat.get("check_context", False)

            for m in regex.finditer(text):
                matched = m.group()
                group = pat.get("group")
                start = m.start()
                end = m.end()
                if group:
                    try:
                        grp = m.group(group)
                        if grp:
                            matched = grp
                            start = m.start(group)
                            end = m.end(group)
                    except IndexError:
                        pass
                if validate and not validate(matched):
                    near_misses.append(
                        PatternMatch(text=matched, type=pat["type"], start=start, end=end, confidence=0.3)
                    )
                    continue
                if check_context and _looks_like_false_positive(text, m.start(), m.end()):
                    continue
                results.append(
                    PatternMatch(text=matched, type=pat["type"], start=start, end=end)
                )

        results.sort(key=lambda r: r.start)
        return results, near_misses
