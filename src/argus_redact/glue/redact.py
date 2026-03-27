"""redact() — public API that composes pure + impure layers."""

from __future__ import annotations

import importlib
import json
import logging
import time
from pathlib import Path

from argus_redact._types import PatternMatch
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
    "de": "argus_redact.lang.de.patterns",
    "uk": "argus_redact.lang.uk.patterns",
    "in": "argus_redact.lang.in_.patterns",
}

_LANG_NER_ADAPTERS = {
    "zh": "argus_redact.lang.zh.ner_adapter",
    "en": "argus_redact.lang.en.ner_adapter",
    "ja": "argus_redact.lang.ja.ner_adapter",
    "ko": "argus_redact.lang.ko.ner_adapter",
    "de": "argus_redact.lang.de.ner_adapter",
    "uk": "argus_redact.lang.uk.ner_adapter",
    "in": "argus_redact.lang.in_.ner_adapter",
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


def _tag_layer(entities: list[PatternMatch], layer: int) -> list[PatternMatch]:
    """Tag entities with their source layer if not already tagged."""
    return [
        PatternMatch(
            text=e.text,
            type=e.type,
            start=e.start,
            end=e.end,
            confidence=e.confidence,
            layer=layer if e.layer == 0 else e.layer,
        )
        for e in entities
    ]


def redact(
    text: str,
    *,
    key: dict | str | None = None,
    lang: str | list[str] = "zh",
    mode: str = "auto",
    seed: int | None = None,
    config: dict | str | None = None,
    names: list[str] | None = None,
    detailed: bool = False,
) -> tuple[str, dict] | tuple[str, dict, dict]:
    """Detect and replace PII in text.

    Args:
        names: List of known names/entities to always redact (no NER needed).

    Returns (redacted_text, key), or (redacted_text, key, details) when detailed=True.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a string, got {type(text).__name__}")

    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Must be one of: {', '.join(VALID_MODES)}")

    # Resolve config from file path
    if isinstance(config, str):
        config_path = Path(config)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config}")
        if config_path.suffix in (".yaml", ".yml"):
            import yaml

            config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        else:
            config = json.loads(config_path.read_text(encoding="utf-8"))

    # Resolve key
    existing_key = None
    key_file = None
    if isinstance(key, str):
        key_file = key
        path = Path(key_file)
        existing_key = json.loads(path.read_text()) if path.exists() else {}
    elif isinstance(key, dict):
        existing_key = dict(key)

    timing = {}
    entities: list[PatternMatch] = []
    langs = [lang] if isinstance(lang, str) else list(lang)

    # Layer 1a: regex (structural PII — phone, ID, bank card, etc.)
    t0 = time.perf_counter()
    layer1 = match_patterns(text, _load_patterns(lang))
    timing["layer_1_ms"] = (time.perf_counter() - t0) * 1000
    entities.extend(_tag_layer(layer1, 1))
    layer1_count = len(layer1)

    # Layer 1b: person name detection
    # Chinese: candidate generation + evidence scoring (handles known_names internally)
    # Other languages: exact match on known_names only
    if "zh" in langs:
        from argus_redact.lang.zh.person import detect_person_names

        t0 = time.perf_counter()
        person_names = detect_person_names(
            text, pii_entities=layer1, known_names=names,
        )
        timing["layer_1b_person_ms"] = (time.perf_counter() - t0) * 1000
        entities.extend(_tag_layer(person_names, 1))
        layer1_count += len(person_names)
    elif names:
        import re as _re

        for name in names:
            if not name:
                continue
            for m in _re.finditer(_re.escape(name), text):
                entities.append(
                    PatternMatch(
                        text=name, type="person",
                        start=m.start(), end=m.end(),
                        confidence=1.0, layer=1,
                    )
                )
                layer1_count += 1

    # Layer 2: NER (auto or ner mode)
    layer2_count = 0
    if mode in ("auto", "ner"):
        from argus_redact.impure.ner import detect_ner

        t0 = time.perf_counter()
        for adapter in _get_ner_adapters(lang):
            ner_entities = detect_ner(text, adapter=adapter)
            layer2_matches = [e.to_pattern_match(layer=2) for e in ner_entities]
            entities.extend(layer2_matches)
            layer2_count += len(layer2_matches)
        timing["layer_2_ms"] = (time.perf_counter() - t0) * 1000

    # Layer 3: Semantic LLM (auto mode only)
    layer3_count = 0
    if mode == "auto":
        semantic_adapter = _get_semantic_adapter()
        if semantic_adapter is not None:
            from argus_redact.impure.semantic import detect_semantic

            t0 = time.perf_counter()
            try:
                sem_entities = detect_semantic(text, adapter=semantic_adapter)
                layer3_matches = [e.to_pattern_match(layer=3) for e in sem_entities]
                entities.extend(layer3_matches)
                layer3_count += len(layer3_matches)
            except Exception:
                logger.warning("Layer 3 semantic detection failed", exc_info=True)
            timing["layer_3_ms"] = (time.perf_counter() - t0) * 1000

    entities = merge_entities(entities)

    redacted, result_key = replace(
        text,
        entities,
        seed=seed,
        key=existing_key,
        config=config,
    )

    if key_file is not None and result_key:
        target = Path(key_file)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(result_key, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(target)

    if detailed:
        reverse_key = {v: k for k, v in result_key.items()}
        entity_details = [
            {
                "original": e.text,
                "replacement": reverse_key.get(e.text, ""),
                "type": e.type,
                "layer": e.layer,
                "start": e.start,
                "end": e.end,
                "confidence": e.confidence,
            }
            for e in entities
        ]
        total_ms = sum(timing.values())
        details = {
            "entities": entity_details,
            "stats": {
                "total": len(entity_details),
                "layer_1": layer1_count,
                "layer_2": layer2_count,
                "layer_3": layer3_count,
                "duration_ms": round(total_ms, 2),
                **{k: round(v, 2) for k, v in timing.items()},
            },
        }
        return redacted, result_key, details

    return redacted, result_key
