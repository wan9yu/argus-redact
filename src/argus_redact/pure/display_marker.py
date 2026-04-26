"""Display marker module — adds a visible marker after fake values for human display.

Used by the pseudonym-llm profile's `display_text` to make synthetic values
recognizable when shown directly to humans (without restore).
"""

from __future__ import annotations

import re


DEFAULT_DISPLAY_MARKER = "ⓕ"  # U+24D5

DISPLAY_MARKER_PRESETS = {
    "circled_f": "ⓕ",  # default, U+24D5
    "superscript_s": "ˢ",  # U+02E2
    "asterisk": "*",
    "chinese": "(假)",
    "none": "",
}


def resolve_marker(marker: str | None) -> str:
    """Resolve a marker preset name or literal string. None -> default."""
    if marker is None:
        return DEFAULT_DISPLAY_MARKER
    if marker in DISPLAY_MARKER_PRESETS:
        return DISPLAY_MARKER_PRESETS[marker]
    return marker


def mark_for_display(text: str, key: dict[str, str], *, marker: str | None = None) -> str:
    """Append `marker` after each fake value (key in `key`) in `text`.

    Idempotent — values already followed by the marker are not double-marked.
    """
    m = resolve_marker(marker)
    if not m or not key:
        return text
    # Sort longest-first to avoid prefix collisions ("张" matching inside "张明").
    sorted_fakes = sorted(key.keys(), key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(f) for f in sorted_fakes))

    def _append(match: re.Match[str]) -> str:
        if text.startswith(m, match.end()):
            return match.group()
        return match.group() + m

    return pattern.sub(_append, text)


def strip_display_markers(text: str, *, marker: str | None = None) -> str:
    """Remove `marker` from `text`."""
    m = resolve_marker(marker)
    if not m:
        return text
    return text.replace(m, "")
