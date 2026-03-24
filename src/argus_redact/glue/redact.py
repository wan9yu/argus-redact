"""redact() — public API that composes pure + impure layers."""

import importlib
import json
from pathlib import Path

from argus_redact.pure.patterns import match_patterns
from argus_redact.pure.replacer import replace
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS

_LANG_PATTERNS = {
    "zh": "argus_redact.lang.zh.patterns",
    "en": "argus_redact.lang.en.patterns",
}

VALID_MODES = ("auto", "fast", "ner")


def _load_patterns(lang: str | list[str]) -> list[dict]:
    """Load regex patterns for the given language(s)."""
    langs = [lang] if isinstance(lang, str) else list(lang)
    all_patterns = list(SHARED_PATTERNS)

    for code in langs:
        if code not in _LANG_PATTERNS:
            raise ValueError(
                f"Unknown language '{code}'. "
                f"Available: {list(_LANG_PATTERNS.keys())}"
            )
        try:
            mod = importlib.import_module(_LANG_PATTERNS[code])
            all_patterns.extend(mod.PATTERNS)
        except ModuleNotFoundError:
            raise ValueError(
                f"Language pack '{code}' is not installed. "
                f"Install with: pip install argus-redact[{code}]"
            )

    return all_patterns


def redact(
    text: str,
    *,
    key: dict | str | None = None,
    lang: str | list[str] = "zh",
    mode: str = "auto",
    seed: int | None = None,
) -> tuple[str, dict]:
    """Detect and replace PII in text. Returns (redacted_text, key)."""
    if not isinstance(text, str):
        raise TypeError(f"text must be a string, got {type(text).__name__}")

    if mode not in VALID_MODES:
        raise ValueError(
            f"Invalid mode '{mode}'. Must be one of: {', '.join(VALID_MODES)}"
        )

    # Resolve key
    existing_key = None
    key_file = None
    if isinstance(key, str):
        key_file = key
        path = Path(key_file)
        existing_key = json.loads(path.read_text()) if path.exists() else {}
    elif isinstance(key, dict):
        existing_key = dict(key)

    # Layer 1: regex
    entities = match_patterns(text, _load_patterns(lang))

    # Layer 2 (NER) and Layer 3 (Semantic) — not yet implemented

    redacted, result_key = replace(text, entities, seed=seed, key=existing_key)

    if key_file is not None and result_key:
        Path(key_file).write_text(
            json.dumps(result_key, ensure_ascii=False, indent=2)
        )

    return redacted, result_key
