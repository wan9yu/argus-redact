"""restore(text, key) -> plaintext. Pure string replacement."""


def restore(text: str, key: dict | str) -> str:
    """Replace pseudonyms with originals using the key.

    Keys are applied longest-first to prevent partial matches.
    """
    if isinstance(key, str):
        import json
        with open(key) as f:
            key = json.load(f)

    if not isinstance(key, dict):
        raise TypeError(
            f"key must be a dict or str (file path), got {type(key).__name__}"
        )

    if not key:
        return text

    # Sort by key length descending — longest match first
    sorted_keys = sorted(key.keys(), key=len, reverse=True)

    result = text
    for replacement in sorted_keys:
        original = key[replacement]
        result = result.replace(replacement, original)

    return result
