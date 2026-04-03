"""restore(text, key) -> plaintext. Pure string replacement."""

from __future__ import annotations


def restore(text: str, key: dict | str) -> str:
    """Replace pseudonyms with originals using the key."""
    if isinstance(key, str):
        import json
        with open(key, encoding="utf-8") as f:
            key = json.load(f)

    if not isinstance(key, dict):
        raise TypeError(f"key must be a dict or str (file path), got {type(key).__name__}")

    if not key:
        return text

    try:
        from argus_redact._core import restore as _rust_restore
        return _rust_restore(text, key)
    except ImportError:
        pass

    # Python fallback
    import re
    sorted_keys = sorted(key.keys(), key=len, reverse=True)
    pattern = "|".join(re.escape(k) for k in sorted_keys)
    regex = re.compile(pattern)
    return regex.sub(lambda m: key[m.group()], text)
