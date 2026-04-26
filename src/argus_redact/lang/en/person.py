"""English person-name detection for L1b fast mode.

Algorithm: scan capitalized-word tokens, identify those in the known surname
list, then look back at 1-2 preceding capitalized tokens (which must be in
the given-name list OR look like an initial/middle name) to assemble the
full person match. No evidence scoring (unlike zh) because English surnames
have minimal overlap with common English words.

Sources for the underlying data:
- ``lang/en/surnames.py`` — U.S. Census 2010 Surname File (public domain)
- ``lang/en/given_names.py`` — SSA Top Names (public domain)
"""

from __future__ import annotations

import re

from argus_redact._types import PatternMatch
from argus_redact.lang.en.given_names import GIVEN_NAME_SET
from argus_redact.lang.en.surnames import SURNAME_SET

# Tokenize into "Capitalized" or "Single-letter+." (initial). Lowercase /
# punctuation tokens are gaps that delimit candidate name spans.
_TOKEN_PAT = re.compile(r"\b[A-Z][a-z]+\b|\b[A-Z]\.")


def detect_person_names(
    text: str,
    *,
    pii_entities: list[PatternMatch] | None = None,  # unused, signature parity with zh
    known_names: list[str] | None = None,
    threshold: float = 0.8,  # unused, signature parity with zh
) -> list[PatternMatch]:
    """Detect English person names via surname-list match + optional given-name boost.

    Returns ``list[PatternMatch]`` with ``type='person'``. Confidence rules:
    - Caller-provided ``known_names`` exact match: 1.0
    - Surname in known list AND first-name token in GIVEN_NAME_SET: 1.0
    - Surname in known list, first-name token unknown: 0.9
    - Surname not in known list: skipped

    Single-token surnames alone (e.g. "Smith") are intentionally NOT matched:
    the algorithm requires at least one preceding capitalized token (given
    name or initial) to avoid false positives on titles, captions, etc.
    """
    results: list[PatternMatch] = []
    seen_spans: set[tuple[int, int]] = set()

    # Phase 1: known_names exact match wins (confidence 1.0)
    if known_names:
        for name in known_names:
            for m in re.finditer(re.escape(name), text):
                span = (m.start(), m.end())
                if span not in seen_spans:
                    results.append(
                        PatternMatch(
                            text=name,
                            type="person",
                            start=m.start(),
                            end=m.end(),
                            confidence=1.0,
                        )
                    )
                    seen_spans.add(span)

    # Phase 2: tokenize, then scan for surnames and look back at preceding tokens.
    tokens = list(_TOKEN_PAT.finditer(text))
    for i, tok in enumerate(tokens):
        word = tok.group()
        if word not in SURNAME_SET:
            continue
        # Look back at preceding 1-2 tokens; they must be ADJACENT in the text
        # (only whitespace between this surname and the prior token).
        if i == 0:
            continue
        prev = tokens[i - 1]
        # Adjacency: at most a small whitespace/dot gap between prev.end() and tok.start()
        gap = text[prev.end() : tok.start()]
        if gap.strip(" \t.") != "":
            # Non-whitespace/dot characters between → not a continuous name
            continue
        # First token (given name candidate)
        first = prev.group()
        # Extend backwards only when the candidate first-name token is itself
        # a known given name. This prevents capturing leading verbs/titles
        # ("Email John Smith" must match "John Smith", not "Email John Smith").
        match_start = prev.start()
        if i >= 2:
            prev2 = tokens[i - 2]
            gap2 = text[prev2.end() : prev.start()]
            prev2_word = prev2.group().rstrip(".")
            if gap2.strip(" \t.") == "" and prev2_word in GIVEN_NAME_SET:
                match_start = prev2.start()
                first = prev2.group()
        span = (match_start, tok.end())
        if span in seen_spans:
            continue
        # Strip trailing dot for given-name lookup
        first_clean = first.rstrip(".")
        confidence = 1.0 if first_clean in GIVEN_NAME_SET else 0.9
        results.append(
            PatternMatch(
                text=text[match_start : tok.end()],
                type="person",
                start=match_start,
                end=tok.end(),
                confidence=confidence,
            )
        )
        seen_spans.add(span)

    return results
