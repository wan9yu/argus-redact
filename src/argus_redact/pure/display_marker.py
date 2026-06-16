"""Display marker module — adds a visible marker after fake values for human display.

Used by the pseudonym-llm profile's `display_text` to make synthetic values
recognizable when shown directly to humans (without restore).

This module is a thin wrapper around `argus_redact._core` (Rust).
"""

from __future__ import annotations

from argus_redact._core import (
    mark_for_display as _core_mark,
    strip_display_markers as _core_strip,
    resolve_marker as _core_resolve,
    preset_marker_chars as _core_preset_chars,
)

DEFAULT_DISPLAY_MARKER = "ⓕ"  # U+24D5

DISPLAY_MARKER_PRESETS: dict[str, str] = {
    "circled_f": "ⓕ",       # default, U+24D5
    "superscript_s": "ˢ",   # U+02E2
    "asterisk": "*",
    "chinese": "(假)",
    "none": "",
}

# Characters that may appear in any preset marker label. Used by `restore()` to
# auto-detect and strip known preset markers attached to keys when the caller
# omitted `display_marker=`. Custom markers (not in DISPLAY_MARKER_PRESETS) are
# NOT included — those still require explicit pass-through.
PRESET_MARKER_CHARS: frozenset[str] = frozenset(_core_preset_chars())


def resolve_marker(marker: str | None) -> str:
    """Resolve a marker preset name or literal string. None -> default."""
    return _core_resolve(marker)


def mark_for_display(text: str, key: dict[str, str], *, marker: str | None = None) -> str:
    """Append `marker` after each fake value (key in `key`) in `text`.

    Idempotent — values already followed by the marker are not double-marked.
    """
    return _core_mark(text, list(key.keys()), marker)


def strip_display_markers(text: str, *, marker: str | None = None) -> str:
    """Remove `marker` from `text`."""
    return _core_strip(text, marker)
