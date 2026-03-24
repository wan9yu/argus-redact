"""redact() — public API that composes pure + impure layers."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.merger import merge_entities
from argus_redact.pure.patterns import match_patterns
from argus_redact.pure.replacer import replace

_LANG_PATTERNS = {
    "zh": "argus_redact.lang.zh.patterns",
    "en": "argus_redact.lang.en.patterns",
    "ja": "argus_redact.lang.ja.patterns",
    "ko": "argus_redact.lang.ko.patterns",
}

_LANG_NER_ADAPTERS = {
    "zh": "argus_redact.lang.zh.ner_adapter",
    "en": "argus_redact.lang.en.ner_adapter",
    "ja": "argus_redact.lang.ja.ner_adapter",
    "ko": "argus_redact.lang.ko.ner_adapter",
}

VALID_MODES = ("auto", "fast", "ner")


def _load_patterns(lang: str | list[str]) -> list[dict]:
    """Load regex patterns for the given language(s)."""
    langs = [lang] if isinstance(lang, str) else list(lang)
    all_patterns = list(SHARED_PATTERNS)

    for code in langs:
        if code not in _LANG_PATTERNS:
            raise ValueError(
                f"Unknown language '{code}'. " f"Available: {list(_LANG_PATTERNS.keys())}"
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


def _get_ner_adapter(lang: str | list[str]):
    """Load and return a NER adapter for the given language. Returns None if unavailable."""

    langs = [lang] if isinstance(lang, str) else list(lang)

    for code in langs:
        if code not in _LANG_NER_ADAPTERS:
            continue
        try:
            mod = importlib.import_module(_LANG_NER_ADAPTERS[code])
            adapter = mod.create_adapter()
            adapter.load()
            return adapter
        except (ModuleNotFoundError, ImportError):
            pass

    return None


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
        raise ValueError(f"Invalid mode '{mode}'. Must be one of: {', '.join(VALID_MODES)}")

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

    # Layer 2: NER (auto or ner mode)
    if mode in ("auto", "ner"):
        adapter = _get_ner_adapter(lang)
        if adapter is not None:
            from argus_redact.impure.ner import detect_ner

            ner_entities = detect_ner(text, adapter=adapter)
            entities.extend(e.to_pattern_match() for e in ner_entities)

    entities = merge_entities(entities)

    redacted, result_key = replace(text, entities, seed=seed, key=existing_key)

    if key_file is not None and result_key:
        Path(key_file).write_text(json.dumps(result_key, ensure_ascii=False, indent=2))

    return redacted, result_key
