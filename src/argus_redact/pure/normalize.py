"""Unicode normalization — strip invisible characters, normalize digit variants.

Used before regex matching to prevent Unicode bypass attacks.
Returns normalized text + offset mapping to recover original positions.

Pipeline:
  1. ASCII fast-path (skip everything if pure ASCII)
  2. Strip invisible/direction-control characters
  3. Replace confusables (Cyrillic/Greek → Latin)
  4. NFKC normalization (fullwidth → halfwidth, superscript → normal)
  5. Contextual digit normalization (Chinese digit sequences → ASCII digits)
"""

from __future__ import annotations

import unicodedata

# Characters to strip before matching (invisible, zero-width, direction control)
_INVISIBLE = frozenset(
    {
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
    }
)

MAX_INPUT_SIZE = 1024 * 1024  # 1MB

# High-frequency confusables: Latin ↔ Cyrillic ↔ Greek
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic → Latin
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u0456": "i",
        "\u04bb": "h",
        "\u0432": "b",
        "\u043a": "k",
        "\u043c": "m",
        "\u0442": "t",
        "\u043d": "h",
        "\u0410": "A",
        "\u0412": "B",
        "\u0415": "E",
        "\u041a": "K",
        "\u041c": "M",
        "\u041d": "H",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0422": "T",
        "\u0425": "X",
        "\u0423": "Y",
        # Greek → Latin
        "\u03bf": "o",
        "\u03b1": "a",
        "\u03b5": "e",
        "\u03b9": "i",
        "\u03ba": "k",
        "\u03bd": "v",
        "\u03c1": "p",
        "\u03c4": "t",
        "\u039f": "O",
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0397": "H",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u03a1": "P",
        "\u03a4": "T",
        "\u03a7": "X",
        "\u0396": "Z",
    }
)

# Chinese digit equivalents (1:1 mapping, no length change)
_CN_DIGIT_MAP = {
    "一": "1",
    "二": "2",
    "三": "3",
    "四": "4",
    "五": "5",
    "六": "6",
    "七": "7",
    "八": "8",
    "九": "9",
    "零": "0",
    "壹": "1",
    "贰": "2",
    "叁": "3",
    "肆": "4",
    "伍": "5",
    "陆": "6",
    "柒": "7",
    "捌": "8",
    "玖": "9",
}
# Separators tolerated inside digit sequences
_DIGIT_SEPS = frozenset(" \t.-/，、·;；:：")
_MIN_DIGIT_SEQ = 7  # shortest PII (phone fragments)


def _normalize_digit_sequences(chars: list[str]) -> None:
    """In-place: replace Chinese digit sequences (7+) with ASCII digits.

    Only converts when a long enough sequence of digit-equivalent characters
    is found. Short sequences like 三月 (1 digit) are left unchanged.
    """
    n = len(chars)
    i = 0
    while i < n:
        ch = chars[i]
        d = _CN_DIGIT_MAP.get(ch) or (ch if ch.isdigit() else None)
        if d is None:
            i += 1
            continue

        # Scan a contiguous digit-equivalent sequence (with optional separators)
        seq_start = i
        digits: list[tuple[int, str]] = [(i, d)]  # (index, ascii_digit)
        i += 1
        while i < n:
            ch = chars[i]
            if ch in _DIGIT_SEPS:
                i += 1
                continue
            d = _CN_DIGIT_MAP.get(ch) or (ch if ch.isdigit() else None)
            if d is None:
                break
            digits.append((i, d))
            i += 1

        # Only normalize if sequence has enough digits AND contains Chinese digits
        has_cn = any(chars[idx] in _CN_DIGIT_MAP for idx, _ in digits)
        if len(digits) >= _MIN_DIGIT_SEQ and has_cn:
            for idx, ascii_d in digits:
                chars[idx] = ascii_d


def normalize_text(text: str) -> tuple[str, list[int] | None]:
    """Normalize text for PII detection, returning offset map.

    Returns:
        (normalized_text, offset_map) where offset_map[i] = original char index.
        offset_map is None when text is unchanged (identity mapping).
    """
    if text.isascii():
        return text, None

    # Step 1: strip invisible chars, build offset map
    chars: list[str] = []
    offset_map: list[int] = []
    for i, ch in enumerate(text):
        if ch not in _INVISIBLE:
            chars.append(ch)
            offset_map.append(i)

    # Step 2: confusables (Cyrillic/Greek → Latin)
    joined = "".join(chars).translate(_CONFUSABLES)

    # Step 3: NFKC normalization
    if not unicodedata.is_normalized("NFKC", joined):
        new_chars: list[str] = []
        new_map: list[int] = []
        for si, ch in enumerate(joined):
            nfkc = unicodedata.normalize("NFKC", ch)
            for c in nfkc:
                new_chars.append(c)
                new_map.append(offset_map[si])
        chars = new_chars
        offset_map = new_map
    else:
        chars = list(joined)

    # Step 4: contextual digit normalization (Chinese digits in 7+ sequences)
    _normalize_digit_sequences(chars)

    result = "".join(chars)
    if result == text:
        return text, None
    return result, offset_map


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
