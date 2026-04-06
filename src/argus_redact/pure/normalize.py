"""Unicode normalization — strip invisible characters, NFKC normalize.

Used before regex matching to prevent Unicode bypass attacks.
Returns normalized text + offset mapping to recover original positions.
"""

from __future__ import annotations

import unicodedata

# Characters to strip before matching (invisible, zero-width, direction control)
_INVISIBLE = frozenset({
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u00ad",  # soft hyphen
    "\ufeff",  # BOM / zero-width no-break space
    "\u200e",  # LTR mark
    "\u200f",  # RTL mark
    "\u202a",  # LTR embedding
    "\u202b",  # RTL embedding
    "\u202c",  # pop directional formatting
    "\u202d",  # LTR override
    "\u202e",  # RTL override
    "\u2066",  # LTR isolate
    "\u2067",  # RTL isolate
    "\u2068",  # first strong isolate
    "\u2069",  # pop directional isolate
})

MAX_INPUT_SIZE = 1024 * 1024  # 1MB


def normalize_text(text: str) -> tuple[str, list[int] | None]:
    """Normalize text for PII detection, returning offset map.

    Steps:
    1. Fast-path: ASCII-only text is returned as-is (no allocation)
    2. Strip invisible/direction-control characters
    3. Apply NFKC normalization (fullwidth→halfwidth, superscript→normal, etc.)

    Returns:
        (normalized_text, offset_map) where offset_map[i] = original char index.
        offset_map is None when text is unchanged (identity mapping).
    """
    if text.isascii():
        return text, None

    # Step 1: strip invisible chars, build offset map
    stripped = []
    offset_map: list[int] = []
    for i, ch in enumerate(text):
        if ch not in _INVISIBLE:
            stripped.append(ch)
            offset_map.append(i)

    stripped_text = "".join(stripped)

    # Step 2: NFKC normalization with per-character offset tracking
    if unicodedata.is_normalized("NFKC", stripped_text):
        if len(stripped_text) == len(text):
            return stripped_text, None
        return stripped_text, offset_map

    # NFKC may expand/contract chars — normalize per-char for accurate mapping
    normalized_chars: list[str] = []
    new_map: list[int] = []
    for si, ch in enumerate(stripped_text):
        nfkc = unicodedata.normalize("NFKC", ch)
        for c in nfkc:
            normalized_chars.append(c)
            new_map.append(offset_map[si])

    return "".join(normalized_chars), new_map


def map_spans_to_original(
    spans: list[tuple[int, int]],
    offset_map: list[int] | None,
    original_len: int,
) -> list[tuple[int, int]]:
    """Map (start, end) spans from normalized text back to original text positions."""
    if offset_map is None:
        return spans
    result = []
    for start, end in spans:
        orig_start = offset_map[start] if start < len(offset_map) else original_len
        if end > 0 and end - 1 < len(offset_map):
            orig_end = offset_map[end - 1] + 1
        else:
            orig_end = original_len
        result.append((orig_start, orig_end))
    return result
