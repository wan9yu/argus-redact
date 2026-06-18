"""redact() — public API that composes pure + impure layers."""

from __future__ import annotations

import importlib
import json
import logging
import os
import time
from pathlib import Path

from argus_redact._safe_io import safe_read_text as _safe_read_text
from argus_redact._types import PatternMatch
from argus_redact.lang._loader import core_patterns
from argus_redact.layers import LAYER_NER, LAYER_SEMANTIC
from argus_redact.pure.grammar import normalize_grammar_en
from argus_redact.pure.hints import (
    boost_cross_layer,
    filter_self_reference,
    get_ner_min_confidence,
    produce_hints,
    should_skip_ner,
)
from argus_redact.pure.lang_detect import detect_languages
from argus_redact.pure.merger import merge_entities
from argus_redact.pure.normalize import MAX_INPUT_SIZE
from argus_redact.pure.replacer import replace
from argus_redact.telemetry import PerfRecord, emit, get_perf_hook

logger = logging.getLogger(__name__)

# Cached telemetry constants (resolved once at import, not per-call)
from argus_redact._core_loader import HAS_CORE as _RUST_CORE, _core


def _telemetry_hook_active() -> bool:
    return get_perf_hook() is not None


def _emit_telemetry(
    text: str,
    timing: dict,
    entities: list,
    langs: list[str],
    mode: str,
) -> None:
    ascii_count = sum(1 for c in text if c.isascii()) if text else 0
    emit(
        PerfRecord(
            version=importlib.import_module("argus_redact").__version__,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            text_len=len(text),
            text_ascii_ratio=round(ascii_count / len(text), 2) if text else 0.0,
            lang=langs,
            mode=mode,
            normalize_ms=round(timing.get("normalize_ms", 0), 2),
            layer_1_ms=round(timing.get("layer_1_ms", 0), 2),
            layer_1b_person_ms=round(timing.get("layer_1b_person_ms", 0), 2),
            layer_2_ms=round(timing.get("layer_2_ms", 0), 2),
            layer_3_ms=round(timing.get("layer_3_ms", 0), 2),
            merge_ms=round(timing.get("merge_ms", 0), 2),
            replace_ms=round(timing.get("replace_ms", 0), 2),
            total_ms=round(sum(timing.values()), 2),
            entities_found=len(entities),
            entity_types=sorted(set(e.type for e in entities)),
            rust_core=_RUST_CORE,
        )
    )


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


_pattern_cache: dict[tuple[str, ...], list[dict]] = {}


def _load_patterns(lang: str | list[str]) -> list[dict]:
    """Load regex patterns for the given language(s). Cached per language combo.

    Pattern DATA is the SSOT in argus-redact-core (RON), read via
    ``core_patterns`` (a thin reader over ``_core.builtin_patterns``). Every
    builtin pattern names its validator as a Rust ``validator`` string, so its
    regex AND validation run inline in Rust (as of v0.7.7 this includes the
    formerly-deferred organization/school/jwt validators). Adapter / non-builtin
    patterns may still carry a Python ``validate`` callable, handled by
    ``pure/patterns.py``. The compiled core is required.
    """
    langs = tuple(lang) if isinstance(lang, list) else (lang,)
    if langs in _pattern_cache:
        return _pattern_cache[langs]

    # Validate language codes up front so the unknown-lang ValueError holds.
    # "shared" is not a requestable lang on its own (it is always merged in
    # below); requesting it raises, which the parity test relies on to skip the
    # synthetic "shared" corpus.
    for code in langs:
        if code not in _LANG_PATTERNS:
            raise ValueError(f"Unknown language '{code}'. Available: {list(_LANG_PATTERNS.keys())}")

    all_patterns = core_patterns("shared")
    for code in langs:
        if code == "shared":
            continue
        all_patterns.extend(core_patterns(code))

    _pattern_cache[langs] = all_patterns
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


def _detect(
    text: str,
    *,
    lang: str | list[str],
    mode: str,
    names: list[str] | None,
    types: list[str] | None,
    types_exclude: list[str] | None,
) -> tuple[list[PatternMatch], list[str], dict, dict]:
    """Run the full detection pipeline (L1 regex + L1b person + L2 NER + L3 LLM + merge).

    Returns:
        entities: final filtered entity list
        langs: resolved language list (after auto-detect)
        timing: numeric per-stage timings (ms) — values summed for total_ms
        layer_stats: counts/status per layer (for detailed/report output)
    """
    timing: dict[str, float] = {}
    entities: list[PatternMatch] = []
    langs = [lang] if isinstance(lang, str) else list(lang)

    # Layer 1 (regex + person) — single Rust engine call. ``detect_l1`` reproduces
    # internally: normalize_text → match_patterns (over _load_patterns) →
    # map_spans_to_original → produce_hints_l1 → get_person_threshold →
    # zh/en person → names-only fallback. It returns the RAW (pre-merge) L1
    # components: ``layer1`` (the L1a regex matches, already tagged LAYER_REGEX,
    # spans mapped back to original text), ``person`` (zh-then-en or names-only,
    # also tagged LAYER_REGEX), the internal L1 hints, and validator ``near_misses``.
    # detect_l1 takes the ORIGINAL text (it normalizes internally).
    t0 = time.perf_counter()
    layer1, person, _l1_hints, near_misses = _core.detect_l1(text, langs, names or [])
    timing["layer_1_ms"] = (time.perf_counter() - t0) * 1000
    entities.extend(layer1)
    entities.extend(person)
    layer1_count = len(layer1) + len(person)

    # Produce the FULL Python hints (all 4 types) from the L1a regex set — consumed
    # by L2 (NER gating), L3, and the report. The 2 L1 hints here
    # (text_intent / self_reference_tier) equal detect_l1's internal ones
    # (golden-locked); the Python set additionally carries pii_density +
    # near_miss_format, which only the L2/L3/report consumers need.
    hints = produce_hints(layer1, text, near_misses=near_misses)

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
            layer2_matches = [e.to_pattern_match(layer=LAYER_NER) for e in ner_entities]
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
                layer3_matches = [e.to_pattern_match(layer=LAYER_SEMANTIC) for e in sem_entities]
                entities.extend(layer3_matches)
                layer3_count += len(layer3_matches)
                layer3_status = "ok"
            except Exception:
                logger.warning("Layer 3 semantic detection failed", exc_info=True)
                layer3_status = "error"
            timing["layer_3_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    pre_merge = entities
    entities = merge_entities(pre_merge, text=text)
    if os.environ.get("ARGUS_ABLATION_NO_BOOST") != "1":
        entities = boost_cross_layer(entities, pre_merge)
    entities = filter_self_reference(entities, hints)
    timing["merge_ms"] = (time.perf_counter() - t0) * 1000

    # Apply type filtering
    if types is not None:
        type_set = set(types)
        entities = [e for e in entities if e.type in type_set]
    elif types_exclude is not None:
        exclude_set = set(types_exclude)
        entities = [e for e in entities if e.type not in exclude_set]

    layer_stats = {
        "layer1_count": layer1_count,
        "layer2_count": layer2_count,
        "layer2_status": layer2_status,
        "layer3_count": layer3_count,
        "layer3_status": layer3_status,
    }
    return entities, langs, timing, layer_stats


def _replace_and_emit(
    text: str,
    entities: list[PatternMatch],
    *,
    salt: int | bytes | None,
    existing_key: dict | None,
    key_file: str | None,
    config: dict | None,
    lang: str | list[str],
    langs: list[str],
    timing: dict,
    mode: str,
    unified_prefix: str | None = None,
) -> tuple[str, dict, dict[str, list[str]]]:
    """Apply replacement, run grammar normalization, emit telemetry, persist key file.

    Mutates `timing` in place by adding `replace_ms`. The caller is responsible
    for any further use of `timing` (e.g., detailed-output stats).

    Returns ``(redacted_text, key, aliases)``. ``aliases`` carries the cross-language
    transliterations emitted by realistic-strategy fakers (empty dict when none ran).
    """
    t0 = time.perf_counter()
    redacted, result_key, aliases = replace(
        text,
        entities,
        salt=salt,
        key=existing_key,
        config=config,
        langs=langs,
        unified_prefix=unified_prefix,
    )
    effective_lang = lang if isinstance(lang, str) else (lang[0] if lang else "zh")
    if effective_lang == "en":
        redacted = normalize_grammar_en(redacted, result_key)
    timing["replace_ms"] = (time.perf_counter() - t0) * 1000

    # Emit telemetry — zero overhead when no hook set
    if _telemetry_hook_active():
        _emit_telemetry(text, timing, entities, langs, mode)

    if key_file is not None and result_key:
        from argus_redact._safe_io import safe_atomic_write_text

        safe_atomic_write_text(
            key_file,
            json.dumps(result_key, ensure_ascii=False, indent=2),
            mode=0o600,
        )

    return redacted, result_key, aliases


def redact(
    text: str,
    *,
    key: dict | str | None = None,
    lang: str | list[str] = "zh",
    mode: str = "fast",
    salt: int | bytes | None = None,
    config: dict | str | None = None,
    names: list[str] | None = None,
    detailed: bool = False,
    report: bool = False,
    with_types: bool = False,
    profile: str | None = None,
    types: list[str] | None = None,
    types_exclude: list[str] | None = None,
    unified_prefix: str | None = None,
    _pre_detected: "list[PatternMatch] | None" = None,
):
    """Detect and replace PII in text.

    Args:
        mode: Detection mode.
            - "fast" (default): regex only. Zero deps, sub-ms, deterministic.
              English names / standalone Chinese names are NOT detected at this level
              — pass them via `names=[...]` or use "ner" / "auto".
            - "ner": regex + NER model (requires spacy/hanlp). Detects bare names.
            - "auto": regex + NER + semantic LLM (requires Ollama). Maximum coverage.
        names: List of known names/entities to always redact (works in fast mode).
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

    if len(text) > MAX_INPUT_SIZE:
        raise ValueError(
            f"Input text ({len(text)} chars) exceeds maximum allowed size "
            f"({MAX_INPUT_SIZE} chars). Split into smaller chunks."
        )

    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Must be one of: {', '.join(VALID_MODES)}")

    if types is not None and types_exclude is not None:
        raise ValueError("types and types_exclude are mutually exclusive")

    # Resolve profile → types filter + strategy overrides
    if profile is not None:
        from argus_redact.specs.profiles import get_profile

        prof = get_profile(profile)
        if types is None and "types" in prof:
            types = prof["types"]
        if "config" in prof:
            # Profile config is base; user config overrides
            profile_config = dict(prof["config"])
            if config:
                profile_config.update(config)
            config = profile_config

    # Resolve config from file path
    if isinstance(config, str):
        config_path = Path(config)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config}")
        if config_path.suffix in (".yaml", ".yml"):
            import yaml

            config = yaml.safe_load(_safe_read_text(config_path))
        else:
            config = json.loads(_safe_read_text(config_path))

    # Resolve key
    existing_key: dict | None = None
    key_file: str | None = None
    if isinstance(key, str):
        key_file = key
        path = Path(key_file)
        existing_key = (
            json.loads(_safe_read_text(path)) if path.exists() else {}
        )
    elif isinstance(key, dict):
        existing_key = dict(key)

    if lang == "auto":
        lang = detect_languages(text)

    # Detection is unified on ONE path for every mode and return shape: _detect
    # (Rust _core.detect_l1 under the hood, which skips L2/L3 in fast mode) runs
    # the detection ONCE, then _replace_and_emit (Rust _core.replace) does the
    # replacement. Fast / detailed / with_types / report differ only in the
    # final return-shape dispatch below, never in how detection runs. The Python
    # fast-mode path therefore detects exactly once and honors ARGUS_ABLATION_HINTS
    # (read inside the Python produce_hints _detect calls).
    #
    # _core.redact_l1 (detect_l1 → merge → filter → replace, all in Rust as a
    # single bundled call) is built, bound, and tested, but is NOT used by this
    # shim — it is the entry point reserved for the upcoming iOS C ABI.
    if _pre_detected is not None:
        entities = _pre_detected
        langs = [lang] if isinstance(lang, str) else list(lang)
        timing: dict[str, float] = {}
        layer_stats = {
            "layer1_count": 0,
            "layer2_count": 0,
            "layer2_status": "skipped",
            "layer3_count": 0,
            "layer3_status": "skipped",
        }
    else:
        entities, langs, timing, layer_stats = _detect(
            text,
            lang=lang,
            mode=mode,
            names=names,
            types=types,
            types_exclude=types_exclude,
        )

    redacted, result_key, _aliases = _replace_and_emit(
        text,
        entities,
        salt=salt,
        existing_key=existing_key,
        key_file=key_file,
        config=config,
        lang=lang,
        langs=langs,
        timing=timing,
        mode=mode,
        unified_prefix=unified_prefix,
    )

    # Return-shape dispatch — precedence (locked by tests/core/test_redact_return_shapes.py):
    #   1. report=True    → RedactReport object (richest; supersedes everything)
    #   2. detailed=True  → 3-tuple (redacted, key, details_dict)
    #   3. with_types=True → 3-tuple (redacted, key, types_dict)
    #   4. default        → 2-tuple (redacted, key)
    # When both `detailed` and `with_types` are set, `detailed` wins (its
    # details_dict already carries per-entity type info, so no caller-visible loss).

    if report or detailed:
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
            "layer_1": layer_stats["layer1_count"],
            "layer_2": layer_stats["layer2_count"],
            "layer_2_status": layer_stats["layer2_status"],
            "layer_3": layer_stats["layer3_count"],
            "layer_3_status": layer_stats["layer3_status"],
            "duration_ms": round(total_ms, 2),
            **{k: round(v, 2) for k, v in timing.items()},
        }

        if report:
            # Precedence 1: report wins over everything
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

        # Precedence 2: detailed (no report) — wins over with_types
        return redacted, result_key, {"entities": entity_details, "stats": stats}

    if with_types:
        # Precedence 3: with_types only — build replacement → PII type mapping
        reverse_key = {v: k for k, v in result_key.items()}
        type_map = {}
        for e in entities:
            replacement = reverse_key.get(e.text, "")
            if replacement:
                type_map[replacement] = e.type
        return redacted, result_key, type_map

    # Precedence 4: default
    return redacted, result_key
