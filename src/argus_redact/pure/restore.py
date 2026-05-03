"""restore(text, key) -> plaintext. Pure string replacement."""

from __future__ import annotations

import functools
import re as _re
from typing import Mapping

from argus_redact.pure.display_marker import PRESET_MARKER_CHARS, strip_display_markers
from argus_redact.pure.grammar import SELF_REF_PRONOUNS, restore_grammar_en
from argus_redact.pure.reserved_range_scanner import scan_for_pollution


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


# Marker class compiled once at module load — same chars regardless of key dict.
_PRESET_MARKER_CLASS = (
    "[" + "".join(_re.escape(c) for c in PRESET_MARKER_CHARS) + "]"
    if PRESET_MARKER_CHARS
    else ""
)


@functools.lru_cache(maxsize=128)
def _compile_decoration_pattern(keys_frozen: frozenset[str]) -> _re.Pattern | None:
    """Cache the auto-detect decoration regex per key set.

    Matches ``(key)(preset_marker_chars+)`` so ``restore()`` can substitute
    the key→original inline while preserving the trailing marker. ``None``
    when there are no keys or no preset markers.
    """
    if not keys_frozen or not _PRESET_MARKER_CLASS:
        return None
    sorted_keys = sorted(keys_frozen, key=len, reverse=True)
    keys_alt = "|".join(_re.escape(k) for k in sorted_keys)
    return _re.compile(f"({keys_alt})({_PRESET_MARKER_CLASS}+)")

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


def restore(
    text: str,
    key: dict[str, str] | str,
    *,
    aliases: dict[str, tuple[str, ...]] | None = None,
    display_marker: str | None = None,
) -> str:
    """Replace pseudonyms with originals using the key.

    `aliases` (v0.6.0+): optional dict mapping a fake to alternate
    transliterations. Each alias is also matched and mapped back to the
    fake's original. Useful when the LLM rewrites Chinese names into pinyin
    or English addresses into 中文.

    If `display_marker` is provided, strip THAT marker from `text` before key
    lookup. If omitted (v0.6.0+), `restore` auto-detects known preset markers
    from `DISPLAY_MARKER_PRESETS` (`ⓕ`, `*`, `(假)`, `ˢ`) attached after a
    key token: the marker stays in the output but the key is restored
    underneath (e.g. `"19999123456ⓕ"` -> `"13800138000ⓕ"`). Custom markers
    not in the preset list still require explicit `display_marker=`
    pass-through. See `PRESET_MARKER_CHARS` in `pure/display_marker.py` for
    the canonical preset character set.
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

    # Merge aliases into the lookup if provided. Each alias points at the same
    # original as its canonical fake — the alternation matches both forms and
    # maps them back. Aliases for fakes not in `key` are ignored.
    if aliases:
        flat: dict[str, str] = dict(key)
        for fake, alias_tuple in aliases.items():
            original = key.get(fake)
            if original is None:
                continue
            for alias in alias_tuple:
                flat[alias] = original
        key = flat

    if not isinstance(key, dict):
        key = dict(key)

    # Auto-detect known preset display markers when caller didn't pass
    # display_marker=. For each occurrence of `key + preset_marker_chars+` in
    # text, replace inline with `value + same_marker_chars` so the marker stays
    # attached to the restored value. Custom markers (not in the preset set)
    # are left alone — caller must pass `display_marker=` for those.
    #
    # This is conservative: stand-alone preset chars (e.g. `*` in regular
    # prose) are NOT stripped because they are not adjacent to a key.
    if display_marker is None:
        decoration_pattern = _compile_decoration_pattern(frozenset(key))
        if decoration_pattern is not None:
            text = decoration_pattern.sub(
                lambda m: key.get(m.group(1), m.group(1)) + m.group(2),
                text,
            )

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
