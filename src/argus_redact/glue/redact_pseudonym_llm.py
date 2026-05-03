"""Public entry point for the pseudonym-llm profile.

Returns a PseudonymLLMResult dataclass with three text forms sharing one key dict.
"""

from __future__ import annotations

from argus_redact._types import PseudonymLLMResult
from argus_redact.glue import redact as _redact_module
from argus_redact.pure.display_marker import mark_for_display, resolve_marker
from argus_redact.pure.normalize import MAX_INPUT_SIZE
from argus_redact.pure.replacer import VALID_STRATEGIES
from argus_redact.pure.reserved_range_scanner import scan_for_pollution
from argus_redact.specs.profiles import get_profile



class PseudonymPollutionError(ValueError):
    """Raised when input to pseudonym-llm already contains reserved-range values.

    Re-redacting realistic-mode output would silently corrupt the key dict
    (the same fake value cannot map back to two different originals). Callers
    should restore() first, or pass ``_polluted_input_ok=True`` if the
    collision risk has been accepted.
    """


def _check_input_pollution(
    text: str,
    *,
    reserved_names: dict[str, tuple[str, ...]] | None = None,
) -> None:
    """Raise PseudonymPollutionError if `text` contains any reserved-range values."""
    hits = scan_for_pollution(text, reserved_names=reserved_names)
    if hits:
        start, _, type_name = hits[0]
        raise PseudonymPollutionError(
            f"Input contains {len(hits)} reserved-range value(s); "
            f"call restore() first or pass _polluted_input_ok=True. "
            f"First hit: type={type_name} at offset {start}"
        )


def redact_pseudonym_llm(
    text: str,
    *,
    display_marker: str | None = None,
    salt: bytes | None = None,
    lang: str | list[str] = "zh",
    mode: str = "fast",
    names: list[str] | None = None,
    types: list[str] | None = None,
    types_exclude: list[str] | None = None,
    strict_input: bool = True,
    _polluted_input_ok: bool = False,
    existing_key: dict[str, str] | None = None,
    reserved_names: dict[str, tuple[str, ...]] | None = None,
    strategy_overrides: dict[str, str] | None = None,
    unified_prefix: str | None = None,
) -> PseudonymLLMResult:
    """Redact `text` with the pseudonym-llm profile, returning three text forms.

    - audit_text: placeholder labels (e.g., "[TEL-79329]") for compliance archive
    - downstream_text: realistic reserved-range fake (for LLM input)
    - display_text: realistic + marker (for human display)

    All three are reversible via the unified `key` dict using restore().

    Detection runs ONCE and the resulting entity set is fed into two replacement
    passes (realistic + audit). Cost is one detection plus two cheap replaces,
    independent of mode.

    Two opt-out paths for the input pollution check:
    - ``strict_input=False`` — public toggle that disables ALL input validation
      (pollution check today; future strictness checks may be added).
    - ``_polluted_input_ok=True`` — narrow "I accept the collision risk for THIS
      call's pollution check"; underscore-prefix marks it as advanced usage.

    `existing_key` (advanced) — pre-existing fake→original mappings to honor.
    Same original value present in both `text` and `existing_key.values()` reuses
    the same fake. Used by ``StreamingRedactor`` for cross-chunk consistency.

    `reserved_names` — overrides the canonical fake-name tables on a per-type
    basis. Pass ``{"person_zh": ()}`` to disable zh canonical-name pollution
    detection (useful when real users may legitimately be named 张三/李四).
    Pass a custom tuple to use a different list. Default ``None`` keeps the
    built-in tables active.

    `strategy_overrides` — per-call mapping from entity type to strategy
    name (e.g., ``{"phone": "remove", "address": "realistic"}``). Overrides
    the active profile's strategy for the realistic (downstream) pass only;
    the audit pass always emits placeholders regardless. A type listed here
    that isn't in the profile is added to both the realistic and audit
    type sets. Strategy names must be in
    ``argus_redact.pure.replacer.VALID_STRATEGIES``.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a string, got {type(text).__name__}")
    if len(text) > MAX_INPUT_SIZE:
        raise ValueError(
            f"Input text ({len(text)} chars) exceeds maximum allowed size "
            f"({MAX_INPUT_SIZE} chars). Split into smaller chunks."
        )
    if mode not in _redact_module.VALID_MODES:
        raise ValueError(
            f"Invalid mode '{mode}'. Must be one of: {', '.join(_redact_module.VALID_MODES)}"
        )
    if types is not None and types_exclude is not None:
        raise ValueError("types and types_exclude are mutually exclusive")

    if strategy_overrides:
        for ent_type, strategy in strategy_overrides.items():
            if strategy not in VALID_STRATEGIES:
                raise ValueError(
                    f"Invalid strategy '{strategy}' for type '{ent_type}'. "
                    f"Must be one of: {', '.join(VALID_STRATEGIES)}"
                )

    if strict_input and not _polluted_input_ok:
        _check_input_pollution(text, reserved_names=reserved_names)

    profile = get_profile("pseudonym-llm")
    if strategy_overrides:
        # Per-key copy needed because we mutate nested dicts below; the
        # streaming hot path (no overrides) keeps the cheap shallow copy.
        realistic_config = {k: dict(v) for k, v in profile["config"].items()}
        for ent_type, strategy in strategy_overrides.items():
            if ent_type in realistic_config:
                realistic_config[ent_type]["strategy"] = strategy
            else:
                realistic_config[ent_type] = {"strategy": strategy}
    else:
        realistic_config = dict(profile["config"])
    # Audit pass uses the (possibly extended) type set with "remove" strategy
    # so audit_text always contains [TYPE-NNNNN] placeholders.
    audit_config = {ent_type: {"strategy": "remove"} for ent_type in realistic_config}

    seed = _salt_to_bytes(salt)

    resolved_lang = lang
    if resolved_lang == "auto":
        from argus_redact.pure.lang_detect import detect_languages

        resolved_lang = detect_languages(text)

    entities, langs, timing, _layer_stats = _redact_module._detect(
        text,
        lang=resolved_lang,
        mode=mode,
        names=names,
        types=types,
        types_exclude=types_exclude,
    )

    downstream_text, key, realistic_aliases = _redact_module._replace_and_emit(
        text,
        entities,
        seed=seed,
        existing_key=existing_key,
        key_file=None,
        config=realistic_config,
        lang=resolved_lang,
        langs=langs,
        timing=dict(timing),
        mode=mode,
        unified_prefix=unified_prefix,
    )
    audit_text, audit_key, _audit_aliases = _redact_module._replace_and_emit(
        text,
        entities,
        seed=seed,
        existing_key=None,
        key_file=None,
        config=audit_config,
        lang=resolved_lang,
        langs=langs,
        timing=dict(timing),
        mode=mode,
        unified_prefix=unified_prefix,
    )

    marker = resolve_marker(display_marker)
    display_text = mark_for_display(downstream_text, key, marker=marker)

    # Detection ran once with one seed; both replace passes use disjoint
    # output spaces (realistic digits/Chinese vs [TYPE-NNNNN] placeholders),
    # so a simple union is collision-free by construction.
    unified_key = {**key, **audit_key}
    # Aliases only attach to realistic-pass fakers; audit placeholders never
    # have transliterations. Skip empty alias lists to keep the dict tight.
    unified_aliases = {
        fake: tuple(realistic_aliases.get(fake, ()))
        for fake in unified_key
        if realistic_aliases.get(fake)
    }

    return PseudonymLLMResult(
        audit_text=audit_text,
        downstream_text=downstream_text,
        display_text=display_text,
        key=unified_key,
        aliases=unified_aliases,
    )


def _salt_to_bytes(salt: bytes | None) -> bytes | None:
    """Pass user-supplied salt through to ``replace()`` as bytes.

    v0.6.0 truncated to 8 bytes + 63 bits; v0.6.1+ preserves the full salt so
    HMAC-SHA256 inside the realistic faker path receives the entropy the caller
    asked for. Returns ``None`` only when caller explicitly omitted salt — in
    which case ``_resolve_salt`` (commit 3) will raise rather than silently
    falling back to ``b""``.
    """
    if salt is None:
        return None
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError(f"salt must be bytes, got {type(salt).__name__}")
    return bytes(salt)
