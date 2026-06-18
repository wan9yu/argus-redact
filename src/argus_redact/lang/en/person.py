"""English person-name detection — thin shim over the Rust ``_core``.

Algorithm (now in the Rust ``person_en`` detector): scan capitalized-word
tokens, identify those in the known surname list, then look back at 1-2
preceding capitalized tokens (a known given name or an initial) to assemble the
full person match. No evidence scoring (unlike zh) because English surnames
have minimal overlap with common English words. The surname / given-name pools
(U.S. Census 2010 surnames + SSA top given names, both public domain) are
embedded as RON in the core. This module only marshals the result across the
FFI boundary; the behavior is verified bit-identical to the former pure-Python
implementation.
"""

from __future__ import annotations

from argus_redact._core_loader import _core
from argus_redact._types import PatternMatch


def detect_person_names(
    text: str,
    *,
    known_names: list[str] | None = None,
) -> list[PatternMatch]:
    """Detect English person names via surname-list match + optional given-name boost.

    Returns ``list[PatternMatch]`` with ``type='person'``. Confidence rules:
    - Caller-provided ``known_names`` exact match: 1.0
    - Surname in known list AND first-name token in the given-name set: 1.0
    - Surname in known list, first-name token unknown: 0.9
    - Surname not in known list: skipped

    Single-token surnames alone (e.g. "Smith") are intentionally NOT matched:
    the algorithm requires at least one preceding capitalized token (given
    name or initial) to avoid false positives on titles, captions, etc.
    """
    return [
        PatternMatch(
            text=r.text,
            type=r.type,
            start=r.start,
            end=r.end,
            confidence=r.confidence,
            layer=r.layer,
        )
        for r in _core.detect_person_names_en(text, known_names)
    ]
