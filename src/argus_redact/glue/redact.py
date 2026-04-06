"""redact() — public API that composes pure + impure layers."""

from __future__ import annotations

import importlib
import json
import logging
import time
from pathlib import Path

import re as _re

from argus_redact._types import PatternMatch
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.pure.grammar import normalize_grammar_en
from argus_redact.pure.hints import (
    boost_cross_layer, filter_self_reference, get_ner_min_confidence,
    get_person_threshold, produce_hints, should_skip_ner,
)
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
    "br": "argus_redact.lang.br.patterns",
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
    report: bool = False,
    with_types: bool = False,
    profile: str | None = None,
    types: list[str] | None = None,
    types_exclude: list[str] | None = None,
):
    """Detect and replace PII in text.

    Args:
        names: List of known names/entities to always redact (no NER needed).
        report: Return a RedactReport with risk assessment and audit info.
        with_types: Return a 3-tuple (redacted, key, types) where types maps replacement→PII type.
        profile: Compliance profile name ("default", "pipl", "gdpr", "hipaa").
        types: Whitelist of PII type names to detect.
        types_exclude: Blacklist of PII type names to skip.

    Returns:
        (redacted_text, key) by default.
        (redacted_text, key, details) when detailed=True.
        RedactReport when report=True.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a string, got {type(text).__name__}")

    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Must be one of: {', '.join(VALID_MODES)}")

    if types is not None and types_exclude is not None:
        raise ValueError("types and types_exclude are mutually exclusive")

    # Resolve profile → types filter
    if profile is not None:
        from argus_redact.specs.profiles import get_profile
        prof = get_profile(profile)
        if types is None and "types" in prof:
            types = prof["types"]

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

    # Produce hints from L1a results — consumed by L1b, L2, L3, and tier filter
    hints = produce_hints(layer1, text)

    # Layer 1b: person name detection
    # Hint-driven: threshold adjusts based on text_intent
    person_threshold = get_person_threshold(hints)

    if "zh" in langs:
        from argus_redact.lang.zh.person import detect_person_names

        t0 = time.perf_counter()
        person_names = detect_person_names(
            text, pii_entities=layer1, known_names=names,
            threshold=person_threshold,
        )
        timing["layer_1b_person_ms"] = (time.perf_counter() - t0) * 1000
        entities.extend(_tag_layer(person_names, 1))
        layer1_count += len(person_names)
    elif names:
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

    # Layer 2: NER (auto or ner mode), hint-gated
    layer2_count = 0
    layer2_status = "skipped"
    if mode in ("auto", "ner") and not should_skip_ner(hints):
        from argus_redact.impure.ner import detect_ner

        ner_confidence = get_ner_min_confidence(hints)
        t0 = time.perf_counter()
        adapters = _get_ner_adapters(lang)
        if not adapters and mode == "ner":
            logger.warning(
                "mode='ner' but no NER models available. "
                "Install language extras: pip install argus-redact[zh] or [en]"
            )
            layer2_status = "no_model"
        for adapter in adapters:
            ner_entities = detect_ner(text, adapter=adapter, min_confidence=ner_confidence)
            layer2_matches = [e.to_pattern_match(layer=2) for e in ner_entities]
            entities.extend(layer2_matches)
            layer2_count += len(layer2_matches)
        if adapters:
            layer2_status = "ok"
        timing["layer_2_ms"] = (time.perf_counter() - t0) * 1000

    # Layer 3: Semantic LLM (auto mode only)
    layer3_count = 0
    layer3_status = "skipped"
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
                layer3_status = "ok"
            except Exception:
                logger.warning("Layer 3 semantic detection failed", exc_info=True)
                layer3_status = "error"
            timing["layer_3_ms"] = (time.perf_counter() - t0) * 1000

    pre_merge = entities
    entities = merge_entities(pre_merge, text=text)

    # Cross-layer agreement: boost confidence when L1+L2 agree
    entities = boost_cross_layer(entities, pre_merge)

    # Self-reference tier filter: driven by hints
    entities = filter_self_reference(entities, hints)

    # Apply type filtering
    if types is not None:
        type_set = set(types)
        entities = [e for e in entities if e.type in type_set]
    elif types_exclude is not None:
        exclude_set = set(types_exclude)
        entities = [e for e in entities if e.type not in exclude_set]

    redacted, result_key = replace(
        text,
        entities,
        seed=seed,
        key=existing_key,
        config=config,
    )

    # Normalize grammar after first-person replacement (English only)
    effective_lang = lang if isinstance(lang, str) else (lang[0] if lang else "zh")
    if effective_lang == "en":
        redacted = normalize_grammar_en(redacted, result_key)

    if key_file is not None and result_key:
        target = Path(key_file)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(result_key, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(target)

    if with_types and not detailed and not report:
        # Build replacement → PII type mapping
        reverse_key = {v: k for k, v in result_key.items()}
        type_map = {}
        for e in entities:
            replacement = reverse_key.get(e.text, "")
            if replacement:
                type_map[replacement] = e.type
        return redacted, result_key, type_map

    if detailed or report:
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
        stats = {
            "total": len(entity_details),
            "layer_1": layer1_count,
            "layer_2": layer2_count,
            "layer_2_status": layer2_status,
            "layer_3": layer3_count,
            "layer_3_status": layer3_status,
            "duration_ms": round(total_ms, 2),
            **{k: round(v, 2) for k, v in timing.items()},
        }

        if report:
            from argus_redact._types import RedactReport
            from argus_redact.pure.risk import assess_risk
            from argus_redact.specs import lookup

            # Build risk input with cached sensitivity lookup
            sens_cache: dict[str, int] = {}
            risk_entities = []
            for e in entity_details:
                t = e["type"]
                if t not in sens_cache:
                    typedefs = lookup(t)
                    sens_cache[t] = typedefs[0].sensitivity if typedefs else 2
                risk_entities.append({"type": t, "sensitivity": sens_cache[t]})
            risk = assess_risk(risk_entities, lang=lang if isinstance(lang, str) else lang[0])

            return RedactReport(
                redacted_text=redacted,
                key=result_key,
                entities=tuple(entity_details),
                stats=stats,
                risk=risk,
            )

        return redacted, result_key, {"entities": entity_details, "stats": stats}

    return redacted, result_key
