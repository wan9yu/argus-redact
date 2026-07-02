"""redact() — public API that composes pure + impure layers."""

from __future__ import annotations

import functools
import importlib
import json
import logging
import os
import time
import warnings
from pathlib import Path

from argus_redact._safe_io import safe_read_text as _safe_read_text
from argus_redact._types import PatternMatch
from argus_redact.exceptions import LayerUnavailableError
from argus_redact.lang._loader import core_patterns
from argus_redact.layers import LAYER_NER, LAYER_SEMANTIC
from argus_redact.pure.grammar import normalize_grammar_en
from argus_redact.pure.hints import (
    _apply_ablation,
    boost_cross_layer,
    filter_self_reference,
    get_ner_min_confidence,
    should_skip_ner,
)
from argus_redact.pure.lang_detect import detect_languages
from argus_redact.pure.merger import merge_entities
from argus_redact.pure.normalize import MAX_INPUT_SIZE
from argus_redact.pure.replacer import SecurityWarning, replace
from argus_redact.telemetry import PerfRecord, emit, get_perf_hook

logger = logging.getLogger(__name__)

# Cached telemetry constants (resolved once at import, not per-call)
from argus_redact._core_loader import HAS_CORE as _RUST_CORE  # noqa: E402
from argus_redact._core_loader import _core  # noqa: E402


@functools.lru_cache(maxsize=1)
def _warn_ablation_once() -> None:
    """Warn ONCE per process if any research ablation env toggle is active.

    These toggles ship in the wheel (research ablation hooks); a privacy tool
    should not silently run a recall-degrading research mode. The env is read
    INSIDE the function so a test can set the env, clear the cache, and observe
    the warning. The lru_cache(maxsize=1) keyed on the empty arg tuple makes it
    fire at most once until ``cache_clear()``.
    """
    active = [v for v in ("ARGUS_ABLATION_HINTS", "ARGUS_ABLATION_NO_BOOST") if os.environ.get(v)]
    if active:
        logger.warning("research ablation toggle(s) active: %s — recall may be degraded", active)


def _ablation_enabled_hints() -> set[str] | None:
    """Resolve the ARGUS_ABLATION_HINTS research hook from the environment (glue).

    The env read lives here (impure glue), not in the pure layer. Returns the
    enabled hint-type set for ``_apply_ablation``:
      unset / "all" → None (keep all); "off" → empty set (drop all);
      comma-separated names → keep only the listed types.
    Recognized: pii_density, text_intent, self_reference_tier, near_miss_format.
    """
    raw = os.environ.get("ARGUS_ABLATION_HINTS")
    if raw is None or raw == "all":
        return None
    if raw == "off":
        return set()
    return {h.strip() for h in raw.split(",") if h.strip()}


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

# Human-readable display names for each shipped pack, keyed by the same codes
# as _LANG_PATTERNS. Single source for the `info` surfaces (CLI `cmd_info` and
# HTTP `/info`) so the two can't drift. A code present in _LANG_PATTERNS but
# absent here falls back to the code itself at the display site.
_LANG_DISPLAY_NAMES = {
    "zh": "Chinese",
    "en": "English",
    "ja": "Japanese",
    "ko": "Korean",
    "de": "German",
    "uk": "British English",
    "in": "Indian",
    "br": "Brazilian Portuguese",
}


def _validate_langs(langs: tuple[str, ...] | list[str]) -> None:
    """Raise ValueError for any requested language code not in the known set.

    'shared' is merged in implicitly and is never requestable on its own.
    """
    for code in langs:
        if code not in _LANG_PATTERNS:
            raise ValueError(f"Unknown language '{code}'. Available: {list(_LANG_PATTERNS.keys())}")


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
    _validate_langs(langs)

    all_patterns = core_patterns("shared")
    for code in langs:
        if code == "shared":
            continue
        all_patterns.extend(core_patterns(code))

    # Always also load `language_neutral` patterns (CN structured numeric IDs)
    # from any source lang not requested — a CN phone/ID number is the same digits
    # regardless of surrounding script, so it must be detectable in en/ja/ko/…
    # text too. The per-pattern flag is the single source of truth (no separate
    # allowlist). Mirrors argus_redact_core::redact_l1::load_patterns so the
    # _load_patterns-based detection parity tests match.
    for src in _LANG_PATTERNS:
        if src in langs:
            continue
        all_patterns.extend(p for p in core_patterns(src) if p.get("language_neutral"))

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


def _gate_en_ner_person(
    text: str,
    matches: list[PatternMatch],
    pii_entities: list,
) -> list[PatternMatch]:
    """Evidence-gate English L2 NER ``person`` candidates through the L1 scorer.

    spaCy English NER (``en_core_web_sm``) is high-recall/noisy on prose; ungated,
    its ``person`` spans enter the result set raw and destroy precision while L1
    English person detection is rigorously evidence-gated. This closes that
    asymmetry by routing each L2 ``person`` candidate through the SAME Rust
    evidence scorer L1 uses (``_core.score_person_candidates_en`` →
    ``person_en::score_person_candidate``): a title / name-like lead / PII
    proximity keeps it, an uncorroborated bare-prose span is dropped. The
    scoring AND the keep/drop threshold are single-sourced in Rust — no scoring is
    duplicated here.

    ``pii_entities`` are the L1 structural-PII matches (the proximity signal,
    matching what L1 person detection receives). Non-``person`` candidates
    (location / organization) pass through untouched.
    """
    person_pos = [i for i, m in enumerate(matches) if m.type == "person"]
    if not person_pos:
        return matches
    candidates = [(matches[i].start, matches[i].end) for i in person_pos]
    keep_mask = _core.score_person_candidates_en(text, candidates, pii_entities or None, None)
    dropped = {pos for pos, keep in zip(person_pos, keep_mask) if not keep}
    if not dropped:
        return matches
    return [m for i, m in enumerate(matches) if i not in dropped]


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
    strict: bool = False,
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
    _validate_langs(langs)
    _warn_ablation_once()

    # Layer 1 (regex + person) — single Rust engine call. ``detect_l1`` reproduces
    # internally: normalize_text → match_patterns (over _load_patterns) →
    # map_spans_to_original → produce_hints_l1 → get_person_threshold →
    # zh/en person → names-only fallback. It returns the RAW (pre-merge) L1
    # components: ``layer1`` (the L1a regex matches, already tagged LAYER_REGEX,
    # spans mapped back to original text), ``person`` (zh-then-en or names-only,
    # also tagged LAYER_REGEX), ``regions`` (evidence-gated zh admin-region
    # ``location`` matches, also tagged LAYER_REGEX), ``job_titles`` (evidence-gated
    # zh occupation ``job_title`` matches, also tagged LAYER_REGEX), ``framework``
    # (evidence-gated zh framework detectors — conditions/``medical`` + hobbies/
    # ``hobby`` — also tagged LAYER_REGEX), the internal L1 hints, and validator
    # ``near_misses``. detect_l1 takes the ORIGINAL text (it normalizes internally).
    t0 = time.perf_counter()
    layer1, person, regions, job_titles, framework, l1_hints, near_misses = _core.detect_l1(
        text, langs, names or []
    )
    timing["layer_1_ms"] = (time.perf_counter() - t0) * 1000
    entities.extend(layer1)
    entities.extend(person)
    entities.extend(regions)
    entities.extend(job_titles)
    entities.extend(framework)
    layer1_count = len(layer1) + len(person) + len(regions) + len(job_titles) + len(framework)

    # Hints come fully from the Rust engine now: detect_l1 emits all 4 types
    # (pii_density / near_miss_format / text_intent / self_reference_tier) in
    # Python order, consumed by L2 (NER gating), L3, and the report. Ablation
    # (the ARGUS_ABLATION_HINTS research hook) is applied Python-side because the
    # Rust core is environment-unaware.
    hints = _apply_ablation(l1_hints, _ablation_enabled_hints())

    # Layer 2: NER (auto or ner mode), hint-gated
    layer2_count = 0
    layer2_status = "skipped"
    if mode in ("auto", "ner"):
        adapters = _get_ner_adapters(lang)
        if not adapters:
            # Availability check runs UNCONDITIONALLY when the layer is requested
            # (NOT gated by should_skip_ner): the caller named the layer and it is
            # unavailable, so surface it even for instruction-intent input.
            if mode == "ner":
                raise LayerUnavailableError(
                    "mode='ner' requested but no NER model is available. "
                    "Install a language extra: pip install argus-redact[zh] or [en]."
                )
            # mode == "auto": best-effort degradation — warn + signal, don't raise.
            warnings.warn(
                "mode='auto': no NER model available; degrading to L1-only "
                "(set strict=True to raise instead).",
                SecurityWarning,
                stacklevel=2,
            )
            layer2_status = "no_model"
            if strict:
                raise LayerUnavailableError("mode='auto' + strict=True: no NER model available.")
        elif not should_skip_ner(hints):
            # Model present AND not hint-skipped → run L2 detection.
            from argus_redact.impure.ner import detect_ner

            ner_confidence = get_ner_min_confidence(hints)
            t0 = time.perf_counter()
            for adapter in adapters:
                ner_entities = detect_ner(text, adapter=adapter, min_confidence=ner_confidence)
                layer2_matches = [e.to_pattern_match(layer=LAYER_NER) for e in ner_entities]
                # English spaCy `person` candidates are evidence-gated through the
                # SAME L1 Rust scorer (proximity signal = the L1a regex matches),
                # so noisy bare-prose spans are dropped instead of entering raw.
                # Other languages / non-person types are unaffected.
                if getattr(adapter, "lang", None) == "en":
                    layer2_matches = _gate_en_ner_person(text, layer2_matches, layer1)
                entities.extend(layer2_matches)
                layer2_count += len(layer2_matches)
            layer2_status = "ok"
            timing["layer_2_ms"] = (time.perf_counter() - t0) * 1000
        # else: model present but hint-skipped → layer2_status stays "skipped"
        #       (the should_skip_ner optimization is preserved for the RUN).

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
            except Exception as exc:
                # Type only, never exc_info=True: a full traceback can embed
                # input fragments from the adapter call frames.
                logger.warning("Layer 3 semantic detection failed: %s", type(exc).__name__)
                layer3_status = "error"
                warnings.warn(
                    "mode='auto': Layer-3 semantic detection failed; continuing "
                    "with L1+L2 (set strict=True to raise instead).",
                    SecurityWarning,
                    stacklevel=2,
                )
                if strict:
                    raise LayerUnavailableError(
                        "mode='auto' + strict=True: Layer-3 semantic detection failed."
                    ) from None
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


def _build_type_map(key: dict[str, str], entities: list[PatternMatch]) -> dict[str, str]:
    """fake → SSOT PII type: invert ``key`` (fake→original) and read each entity's
    ``.type``. Single source shared by ``redact(with_types=True)`` and
    ``redact_pseudonym_llm``'s ``result.types`` (called once per replace pass)."""
    reverse = {original: fake for fake, original in key.items()}
    return {reverse[e.text]: e.type for e in entities if e.text in reverse}


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
    strict: bool = False,
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

    # Fail closed if the compiled core is missing. _core has been mandatory since
    # v0.7.1; without it the fast path would otherwise call detect_l1 on None and
    # raise an opaque AttributeError. Read HAS_CORE off the loader module (not a
    # module-level alias) so the value is resolved per call. A privacy tool must
    # never silently pass text through unredacted when its detection engine is gone.
    import argus_redact._core_loader as _cl

    if not _cl.HAS_CORE:
        raise ImportError(
            "argus-redact requires the compiled _core extension for redaction "
            "(install the wheel or build with maturin)."
        )

    if len(text) > MAX_INPUT_SIZE:
        raise ValueError(
            f"Input text ({len(text)} chars) exceeds maximum allowed size "
            f"({MAX_INPUT_SIZE} chars). Split into smaller chunks."
        )

    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Must be one of: {', '.join(VALID_MODES)}")

    if types is not None and types_exclude is not None:
        raise ValueError("types and types_exclude are mutually exclusive")

    if salt is not None and (
        isinstance(salt, int) or (isinstance(salt, (bytes, bytearray)) and len(salt) < 16)
    ):
        warnings.warn(
            "low-entropy salt: an integer or short salt is grid-searchable on small "
            "PII domains; prefer salt=os.urandom(32) for the forward-secure mapping claim.",
            SecurityWarning,
            stacklevel=2,
        )

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
        existing_key = json.loads(_safe_read_text(path)) if path.exists() else {}
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
    # (applied via _apply_ablation to the Rust-produced hints in _detect).
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
            strict=strict,
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
        # Precedence 3: with_types only — replacement → PII type mapping
        return redacted, result_key, _build_type_map(result_key, entities)

    # Precedence 4: default
    return redacted, result_key
