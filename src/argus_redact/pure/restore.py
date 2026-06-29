"""restore(text, key) -> plaintext. Pure string replacement."""

from __future__ import annotations

from typing import Mapping

from argus_redact.pure.display_marker import strip_display_markers


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

    Delegated to the Rust core (``_core.check_restore_safety``).
    """
    from argus_redact._core import check_restore_safety as _rust_check

    return _rust_check(redacted, llm_output, key)


def wipe_key(key: dict) -> None:
    """Clear a key dict to minimize PII exposure in memory.

    Python strings are immutable and cannot be securely erased from memory,
    but clearing the dict removes references, allowing garbage collection sooner.
    For high-security scenarios, run argus-redact in a short-lived process.
    """
    key.clear()


def restore(
    text: str,
    key: Mapping[str, str],
    *,
    aliases: dict[str, tuple[str, ...]] | None = None,
    display_marker: str | None = None,
) -> str:
    """Replace pseudonyms with originals using the key.

    `key` must be an in-memory mapping. The public
    ``argus_redact.restore(...)`` entry point also accepts a ``str`` path to a
    JSON key file; that file load happens in ``glue/restore.py`` (the I/O
    boundary) so this pure function stays filesystem-free.

    `aliases` (v0.6.0+): optional dict mapping a fake to alternate
    transliterations. Each alias is also matched and mapped back to the
    fake's original. Useful when the LLM rewrites Chinese names into pinyin
    or English addresses into 中文.

    If `display_marker` is provided, strip THAT marker from `text` before key
    lookup. If omitted, no separate marker pass runs: substitution is a single
    left-to-right, longest-key-first scan that advances past each replacement
    (never re-scanning what it just emitted). A decoration marker trailing a
    key token (`ⓕ`, `(假)`, `ˢ`, `*`) is ordinary non-key text, so it survives
    verbatim right after the restored value (e.g. `"19999123456ⓕ"` ->
    `"13800138000ⓕ"`). Pass `display_marker=` only when you want the marker
    removed from the output.
    """
    if not isinstance(key, Mapping):
        raise TypeError(f"key must be a Mapping, got {type(key).__name__}")

    if not key:
        # Even with an empty key, an explicit display_marker should be stripped.
        if display_marker is not None:
            return strip_display_markers(text, marker=display_marker)
        return text

    if not isinstance(key, dict):
        key = dict(key)

    # Delegate substitution + alias merge + decoration markers + grammar to Rust.
    # check_restore_safety and wipe_key remain Python (T8 scope).
    from argus_redact._core import restore as _rust_restore

    # Convert aliases values to lists (Rust expects Vec<String>, not tuples).
    rust_aliases: dict[str, list[str]] | None = None
    if aliases:
        rust_aliases = {k: list(v) for k, v in aliases.items()}

    return _rust_restore(text, key, aliases=rust_aliases, display_marker=display_marker)
