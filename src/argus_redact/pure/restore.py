"""restore(text, key) -> plaintext. Pure string replacement."""

from __future__ import annotations

import re


def restore(text: str, key: dict | str) -> str:
    """Replace pseudonyms with originals using the key.

    Uses regex-based single-pass replacement to avoid injection:
    - All markers are matched simultaneously in one pass
    - Replaced text is never re-scanned for further matches
    - Longest markers are preferred when overlapping
    """
    if isinstance(key, str):
        import json

        with open(key, encoding="utf-8") as f:
            key = json.load(f)

    if not isinstance(key, dict):
        raise TypeError(f"key must be a dict or str (file path), got {type(key).__name__}")

    if not key:
        return text

    # Build regex: longest markers first, all escaped
    sorted_keys = sorted(key.keys(), key=len, reverse=True)
    pattern = "|".join(re.escape(k) for k in sorted_keys)
    regex = re.compile(pattern)

    return regex.sub(lambda m: key[m.group()], text)
