"""redact() — public API that composes pure + impure layers."""

from argus_redact.pure.patterns import match_patterns
from argus_redact.pure.replacer import replace
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS

# Language pack registry
_LANG_PATTERNS = {
    "zh": "argus_redact.lang.zh.patterns",
    "en": "argus_redact.lang.en.patterns",
}

VALID_MODES = ("auto", "fast", "ner")


def _load_patterns(lang: str | list[str]) -> list[dict]:
    """Load regex patterns for the given language(s)."""
    if isinstance(lang, str):
        langs = [lang]
    else:
        langs = list(lang)

    all_patterns = list(SHARED_PATTERNS)

    for code in langs:
        if code not in _LANG_PATTERNS:
            raise ValueError(
                f"Unknown language '{code}'. Available: {list(_LANG_PATTERNS.keys())}"
            )
        import importlib
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

    # Resolve key from file path if needed
    existing_key = None
    key_file = None
    if isinstance(key, str):
        import json
        from pathlib import Path
        key_file = key
        path = Path(key_file)
        if path.exists():
            with open(path) as f:
                existing_key = json.load(f)
        else:
            existing_key = {}
    elif isinstance(key, dict):
        existing_key = dict(key)

    # Generate seed if not provided
    if seed is None:
        import secrets
        seed_value = None  # use random
    else:
        seed_value = seed

    # Layer 1: regex patterns
    patterns = _load_patterns(lang)
    entities = match_patterns(text, patterns)

    # Layer 2: NER (only in 'auto' or 'ner' mode)
    # TODO: implement NER layer

    # Layer 3: Semantic (only in 'auto' mode)
    # TODO: implement semantic layer

    # Replace entities
    redacted, result_key = replace(
        text, entities, seed=seed_value, key=existing_key,
    )

    # Write key file if path was given
    if key_file is not None and result_key:
        import json
        with open(key_file, "w") as f:
            json.dump(result_key, f, ensure_ascii=False, indent=2)

    return redacted, result_key
