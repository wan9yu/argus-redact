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


def normalize_text(text: str) -> tuple[str, list[int]]:
    """Normalize text for PII detection, returning offset map.

    Steps:
    1. Strip invisible/direction-control characters
    2. Apply NFKC normalization (fullwidth→halfwidth, superscript→normal, etc.)

    Returns:
        (normalized_text, offset_map) where offset_map[i] = original char index
        for each char in normalized_text. Used to map detected spans back.
    """
    # Step 1: strip invisible chars, build offset map
    stripped = []
    offset_map: list[int] = []
    for i, ch in enumerate(text):
        if ch not in _INVISIBLE:
            stripped.append(ch)
            offset_map.append(i)

    stripped_text = "".join(stripped)

    # Step 2: NFKC normalization
    # NFKC can change string length (e.g., ﬁ→fi, ½→1⁄2)
    # We need to track offset mapping through NFKC
    normalized = unicodedata.normalize("NFKC", stripped_text)

    if len(normalized) == len(stripped_text):
        # Common case: NFKC didn't change length, offset_map still valid
        return normalized, offset_map

    # NFKC changed length — rebuild offset map
    # Map each normalized char back to the nearest original position
    new_map: list[int] = []
    si = 0  # index into stripped_text
    for ni in range(len(normalized)):
        if si < len(offset_map):
            new_map.append(offset_map[si])
        else:
            # NFKC expanded: map to last known original position
            new_map.append(offset_map[-1] if offset_map else 0)
        # Advance stripped index when NFKC consumed a character
        # Heuristic: advance proportionally
        if si < len(stripped_text):
            si += 1
    return normalized, new_map


def map_spans_to_original(
    spans: list[tuple[int, int]],
    offset_map: list[int],
    original_len: int,
) -> list[tuple[int, int]]:
    """Map (start, end) spans from normalized text back to original text positions."""
    result = []
    for start, end in spans:
        orig_start = offset_map[start] if start < len(offset_map) else original_len
        # end is exclusive, so map end-1 then +1
        if end > 0 and end - 1 < len(offset_map):
            orig_end = offset_map[end - 1] + 1
        else:
            orig_end = original_len
        result.append((orig_start, orig_end))
    return result
