"""restore(text, key) -> plaintext. Pure string replacement."""

from __future__ import annotations

import functools
import re as _re
from typing import Mapping

from argus_redact._types import KeyEntry
from argus_redact.pure.display_marker import strip_display_markers
from argus_redact.pure.grammar import SELF_REF_PRONOUNS, restore_grammar_en
from argus_redact.pure.reserved_range_scanner import scan_for_pollution


def _flatten_key_entries(key: dict) -> dict[str, str]:
    """Expand a {fake: KeyEntry} dict into a flat {fake_or_alias: original} dict.

    Each KeyEntry contributes one entry for its canonical fake and one for
    each alias, all pointing at the same ``original``. A plain str→str dict
    passes through unchanged.
    """
    if not key:
        return {}
    sample = next(iter(key.values()))
    if not isinstance(sample, KeyEntry):
        return key  # already str → str
    flat: dict[str, str] = {}
    for fake, entry in key.items():
        flat[fake] = entry.original
        for alias in entry.aliases:
            flat[alias] = entry.original
    return flat


@functools.lru_cache(maxsize=128)
def _compile_alternation(keys_frozen: frozenset[str]) -> _re.Pattern:
    """Cache compiled alternation regex; key by frozenset of replacement strings.

    Streaming hot path: ``StreamingRestorer.feed`` calls ``restore`` once per
    sentence boundary on the same key dict — caching avoids re-sorting and
    re-compiling the alternation each call. Keyed by frozenset because dict
    insertion order doesn't change matching behavior.
    """
    sorted_keys = sorted(keys_frozen, key=len, reverse=True)
    return _re.compile("|".join(_re.escape(k) for k in sorted_keys))

# Danger patterns: pseudonyms appearing near these suggest exfiltration attempts
_DANGER_PATTERNS = _re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"  # email address
    r"|https?://"  # URL
    r"|(?:send|share|forward|发送|转发|分享|泄露|传给|发给)"  # exfil verbs
)
_DANGER_WINDOW = 100  # chars before/after pseudonym to scan


def check_restore_safety(
    redacted: str,
    llm_output: str,
    key: dict[str, str],
) -> list[str]:
    """Check if LLM output has suspicious pseudonym usage (possible injection).

    Returns a list of warning strings. Empty list = safe.
    Checks:
    1. Pseudonym frequency amplification (appears more than in original)
    2. Pseudonym near danger patterns (email, URL, exfiltration verbs)
    3. Reserved-range value amplification (realistic mode hallucinations)
    """
    warnings = []
    for code in key:
        count_original = redacted.count(code)
        count_llm = llm_output.count(code)

        # Check 1: frequency amplification
        if count_llm > count_original:
            warnings.append(
                f"Pseudonym '{code}' appears {count_llm}x in LLM output "
                f"but only {count_original}x in redacted input — possible injection"
            )

        # Check 2: pseudonym near danger patterns
        if count_llm > 0:
            for m in _re.finditer(_re.escape(code), llm_output):
                start = max(0, m.start() - _DANGER_WINDOW)
                end = min(len(llm_output), m.end() + _DANGER_WINDOW)
                context = llm_output[start:end]
                danger = _DANGER_PATTERNS.search(context)
                if danger:
                    warnings.append(
                        f"Pseudonym '{code}' near danger pattern "
                        f"'{danger.group()}' — possible exfiltration"
                    )
                    break  # one warning per pseudonym is enough

    # Check 3: reserved-range amplification (realistic mode). Counts only —
    # specific values are not enumerated to keep this O(n) over text length.
    redacted_hits = scan_for_pollution(redacted)
    output_hits = scan_for_pollution(llm_output)
    if len(output_hits) > len(redacted_hits):
        delta = len(output_hits) - len(redacted_hits)
        warnings.append(
            f"LLM output contains {delta} additional reserved-range value(s) not in input — "
            f"possible hallucination or fabrication"
        )

    return warnings


def wipe_key(key: dict) -> None:
    """Clear a key dict to minimize PII exposure in memory.

    Python strings are immutable and cannot be securely erased from memory,
    but clearing the dict removes references, allowing garbage collection sooner.
    For high-security scenarios, run argus-redact in a short-lived process.
    """
    key.clear()


def restore(text: str, key: dict | str, *, display_marker: str | None = None) -> str:
    """Replace pseudonyms with originals using the key.

    If `display_marker` is provided, strip markers from `text` before key lookup.
    """
    if display_marker is not None:
        text = strip_display_markers(text, marker=display_marker)

    if isinstance(key, str):
        import json

        with open(key, encoding="utf-8") as f:
            key = json.load(f)

    if not isinstance(key, Mapping):
        raise TypeError(f"key must be a Mapping or str (file path), got {type(key).__name__}")

    if not key:
        return text

    # Rust binding expects a concrete dict — MappingProxyType / other Mapping
    # subclasses are rejected. Normalize once at the boundary.
    if not isinstance(key, dict):
        key = dict(key)

    # v0.5.8: accept KeyEntry-shaped dicts (result.key_entries) and expand
    # aliases into a flat str→str lookup transparently.
    key = _flatten_key_entries(key)

    has_self_ref = any(v in SELF_REF_PRONOUNS for v in key.values())

    try:
        from argus_redact._core import restore as _rust_restore

        result = _rust_restore(text, key)
    except ImportError:
        regex = _compile_alternation(frozenset(key.keys()))
        result = regex.sub(lambda m: key[m.group()], text)

    if has_self_ref:
        result = restore_grammar_en(result)

    return result
