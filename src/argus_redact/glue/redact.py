"""redact() — public API that composes pure + impure layers."""

from __future__ import annotations

import importlib
import json
import logging
from pathlib import Path

from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.merger import merge_entities
from argus_redact.pure.patterns import match_patterns
from argus_redact.pure.replacer import replace

logger = logging.getLogger(__name__)

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


def _get_ner_adapters(lang: str | list[str]) -> list:
    """Load ALL available NER adapters for the given languages."""
    langs = [lang] if isinstance(lang, str) else list(lang)
    adapters = []

    for code in langs:
        if code not in _LANG_NER_ADAPTERS:
            continue
        try:
            mod = importlib.import_module(_LANG_NER_ADAPTERS[code])
            adapter = mod.create_adapter()
            adapter.load()
            adapters.append(adapter)
        except (ModuleNotFoundError, ImportError):
            pass

    return adapters


def _get_semantic_adapter():
    """Create an Ollama semantic adapter. Returns None if unavailable."""
    try:
        from argus_redact.impure.ollama_adapter import OllamaAdapter

        return OllamaAdapter()
    except ImportError:
        return None


def redact(
    text: str,
    *,
    key: dict | str | None = None,
    lang: str | list[str] = "zh",
    mode: str = "auto",
    seed: int | None = None,
    config: dict | None = None,
    detailed: bool = False,
) -> tuple[str, dict] | tuple[str, dict, dict]:
    """Detect and replace PII in text.

    Returns (redacted_text, key), or (redacted_text, key, details) when detailed=True.
    """
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

    # Layer 2: NER (auto or ner mode) — load ALL language adapters
    if mode in ("auto", "ner"):
        from argus_redact.impure.ner import detect_ner

        for adapter in _get_ner_adapters(lang):
            ner_entities = detect_ner(text, adapter=adapter)
            entities.extend(e.to_pattern_match() for e in ner_entities)

    # Layer 3: Semantic LLM (auto mode only)
    if mode == "auto":
        semantic_adapter = _get_semantic_adapter()
        if semantic_adapter is not None:
            from argus_redact.impure.semantic import detect_semantic

            try:
                sem_entities = detect_semantic(text, adapter=semantic_adapter)
                entities.extend(e.to_pattern_match() for e in sem_entities)
            except Exception:
                logger.warning("Layer 3 semantic detection failed", exc_info=True)

    entities = merge_entities(entities)

    # Build reverse mapping: original -> replacement (for details)
    merged_entities = entities

    redacted, result_key = replace(
        text,
        merged_entities,
        seed=seed,
        key=existing_key,
        config=config,
    )

    if key_file is not None and result_key:
        Path(key_file).write_text(json.dumps(result_key, ensure_ascii=False, indent=2))

    if detailed:
        reverse_key = {v: k for k, v in result_key.items()}
        entity_details = [
            {
                "original": e.text,
                "replacement": reverse_key.get(e.text, ""),
                "type": e.type,
                "start": e.start,
                "end": e.end,
                "confidence": e.confidence,
            }
            for e in merged_entities
        ]
        details = {
            "entities": entity_details,
            "stats": {"total": len(entity_details)},
        }
        return redacted, result_key, details

    return redacted, result_key
