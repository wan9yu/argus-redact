"""restore(text, key) -> plaintext. Pure string replacement."""

from __future__ import annotations

import re as _re

from argus_redact.pure.grammar import SELF_REF_PRONOUNS, restore_grammar_en


def check_restore_safety(
    redacted: str, llm_output: str, key: dict[str, str],
) -> list[str]:
    """Check if LLM output has suspicious pseudonym usage (possible injection).

    Returns a list of warning strings. Empty list = safe.
    Warns when a pseudonym appears more times in LLM output than in the
    original redacted text — a sign the LLM is echoing/amplifying pseudonyms.
    """
    warnings = []
    for code in key:
        count_original = redacted.count(code)
        count_llm = llm_output.count(code)
        if count_llm > count_original:
            warnings.append(
                f"Pseudonym '{code}' appears {count_llm}x in LLM output "
                f"but only {count_original}x in redacted input — possible injection"
            )
    return warnings


def wipe_key(key: dict) -> None:
    """Clear a key dict to minimize PII exposure in memory.

    Python strings are immutable and cannot be securely erased from memory,
    but clearing the dict removes references, allowing garbage collection sooner.
    For high-security scenarios, run argus-redact in a short-lived process.
    """
    key.clear()


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

    has_self_ref = any(v in SELF_REF_PRONOUNS for v in key.values())

    try:
        from argus_redact._core import restore as _rust_restore
        result = _rust_restore(text, key)
    except ImportError:
        sorted_keys = sorted(key.keys(), key=len, reverse=True)
        pattern = "|".join(_re.escape(k) for k in sorted_keys)
        regex = _re.compile(pattern)
        result = regex.sub(lambda m: key[m.group()], text)

    if has_self_ref:
        result = restore_grammar_en(result)

    return result
