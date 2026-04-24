"""Script-based language detection for lang='auto' routing.

Detects which installed language pack(s) should process the text, based
on Unicode script ranges. Zero runtime dependencies.

Rules:
  - Hiragana (U+3040-U+309F) or Katakana (U+30A0-U+30FF) → "ja"
  - Hangul syllables (U+AC00-U+D7A3) → "ko"
  - CJK Unified Ideographs (U+4E00-U+9FFF) without ja/ko triggers → "zh"
    (Japanese kanji and Korean hanja share this range — ja/ko win when
     their script-specific chars appear alongside.)
  - ASCII letters >= 3 → add "en"
  - No detection → fallback ["zh"]

Returns a deduplicated list in detection order.
"""

from __future__ import annotations

_LATIN_LETTER_THRESHOLD = 3


def detect_languages(text: str) -> list[str]:
    """Detect which language packs should process the text.

    Returns ["zh"] as fallback when no script triggers. Never returns an empty list.
    """
    if not text:
        return ["zh"]

    # Fast path: ASCII-only input can't contain CJK/Hiragana/Katakana/Hangul.
    # Short-circuit as soon as 3 Latin letters are seen; avoid full codepoint scan.
    # (Matches normalize_text's text.isascii() fast-path convention.)
    if text.isascii():
        letter_count = 0
        for ch in text:
            if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
                letter_count += 1
                if letter_count >= _LATIN_LETTER_THRESHOLD:
                    return ["en"]
        return ["zh"]

    has_ja_script = False
    has_hangul = False
    has_cjk = False
    latin_count = 0

    for ch in text:
        cp = ord(ch)
        if 0x3040 <= cp <= 0x30FF:
            has_ja_script = True
        elif 0xAC00 <= cp <= 0xD7A3:
            has_hangul = True
        elif 0x4E00 <= cp <= 0x9FFF:
            has_cjk = True
        elif ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
            latin_count += 1

    langs: list[str] = []
    if has_ja_script:
        langs.append("ja")
    if has_hangul:
        langs.append("ko")
    if has_cjk and not has_ja_script and not has_hangul:
        langs.append("zh")
    if latin_count >= _LATIN_LETTER_THRESHOLD:
        langs.append("en")

    if not langs:
        return ["zh"]
    return langs
