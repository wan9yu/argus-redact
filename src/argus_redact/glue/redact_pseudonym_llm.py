"""Public entry point for the pseudonym-llm profile.

Returns a PseudonymLLMResult dataclass with three text forms sharing one key dict.
"""

from __future__ import annotations

from argus_redact._types import PatternMatch, PseudonymLLMResult
from argus_redact.glue import redact as _redact_module
from argus_redact.glue.redact import (
    _pre_detected_pipeline,
    _reject_unknown_type_names,
    _validate_redact_inputs,
)
from argus_redact.pure.display_marker import mark_for_display, resolve_marker
from argus_redact.pure.replacer import VALID_STRATEGIES, warn_coverage_restored
from argus_redact.pure.reserved_range_scanner import scan_for_pollution
from argus_redact.specs.profiles import get_profile


class PseudonymPollutionError(ValueError):
    """Raised when input to pseudonym-llm already contains reserved-range values.

    Re-redacting realistic-mode output would silently corrupt the key dict
    (the same fake value cannot map back to two different originals). Callers
    should restore() first, or pass ``_polluted_input_ok=True`` if the
    collision risk has been accepted.
    """


class PseudonymKeyCollisionError(RuntimeError):
    """A single pseudonym code maps to two different originals in one key.

    ``redact_pseudonym_llm`` unions the realistic pass's key with the audit
    pass's key into one restore key. The two spaces are disjoint by construction
    (realistic fakes / bare ``PREFIX-NNNNN`` fallbacks vs. bracketed
    ``[PREFIX-NNNNN]`` audit placeholders), so a collision means overlapping code
    spaces were re-introduced — a regression that would otherwise silently splice
    one original's name onto another's surrogate. Failing loud is the backstop.

    The message names only the colliding code (a surrogate, never PII) — never
    the originals it maps to.
    """


def _put_key_checked(acc: dict[str, str], code: str, original: str) -> None:
    """Insert ``code -> original`` into ``acc``, raising if ``code`` already maps
    to a DIFFERENT original (an identity splice). A repeat of the same mapping is
    idempotent (first-seen preserved)."""
    prior = acc.get(code)
    if prior is not None and prior != original:
        raise PseudonymKeyCollisionError(
            f"pseudonym code {code!r} maps to two different originals; the "
            "realistic and audit key spaces must stay disjoint"
        )
    acc[code] = original


def _merge_pseudonym_keys(
    realistic_key: dict[str, str], audit_key: dict[str, str]
) -> dict[str, str]:
    """Union the realistic and audit keys into one restore key, raising
    ``PseudonymKeyCollisionError`` if any code maps to two different originals.

    Replaces the pre-fix blind ``{**realistic_key, **audit_key}``, whose silent
    last-writer-wins let an audit code overwrite a colliding realistic (LLM-facing)
    mapping."""
    unified = dict(realistic_key)
    for code, original in audit_key.items():
        _put_key_checked(unified, code, original)
    return unified


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
    salt: int | bytes | None = None,
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
    _pre_detected: "list[PatternMatch] | None" = None,
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

    `_pre_detected` (advanced) — entities already detected over `text`; skips internal detection
    (used by streaming detect-once).

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
    _validate_redact_inputs(text, mode, types, types_exclude)

    if strategy_overrides:
        _reject_unknown_type_names(set(strategy_overrides), "strategy_overrides")
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

    resolved_salt = _salt_to_bytes(salt)

    resolved_lang = lang
    if resolved_lang == "auto":
        from argus_redact.pure.lang_detect import detect_languages

        resolved_lang = detect_languages(text)

    _restored_types: list[str] = []
    if _pre_detected is not None:
        # Shared with redact()'s _pre_detected branch — see _pre_detected_pipeline.
        # This file had a byte-identical copy of that block; the copy is what let
        # the post-merge coverage leak survive here after redact() was fixed.
        entities, _restored = _pre_detected_pipeline(_pre_detected, types, types_exclude, text)
        _restored_types.extend(_restored)
        langs = resolved_lang if isinstance(resolved_lang, list) else [resolved_lang]
        timing = {}
    else:
        entities, langs, timing, _layer_stats = _redact_module._detect(
            text,
            lang=resolved_lang,
            mode=mode,
            names=names,
            types=types,
            types_exclude=types_exclude,
            restored_types=_restored_types,
        )

    warn_coverage_restored(_restored_types)

    # Audit pass: every DETECTED type gets the "remove_bracketed" strategy, so
    # audit_text is entirely bracketed [PREFIX-NNNNN] placeholders. Keyed by the
    # detected entity types (union the configured types too), NOT just
    # realistic_config — a detected type absent from the profile config (e.g.
    # ``us_passport``) would otherwise fall through to its registry-default
    # strategy ("remove", bare PREFIX-NNNNN) and re-open the collision. The
    # brackets are load-bearing, not cosmetic: they put every audit code in a
    # namespace DISJOINT from any realistic code (a realistic fake or bare
    # PREFIX-NNNNN pool-exhaustion fallback never contains "["), so the two
    # passes' keys can never collide when unified below. Plain "remove" emitted
    # bare PREFIX-NNNNN — identical to the realistic pass's person fallback —
    # which let the audit mapping silently overwrite an LLM-facing one on the
    # union (an identity splice; see _merge_pseudonym_keys).
    audit_types = set(realistic_config) | {e.type for e in entities}
    audit_config = {ent_type: {"strategy": "remove_bracketed"} for ent_type in audit_types}

    downstream_text, key, realistic_aliases = _redact_module._replace_and_emit(
        text,
        entities,
        salt=resolved_salt,
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
        salt=resolved_salt,
        existing_key=None,
        key_file=None,
        config=audit_config,
        lang=resolved_lang,
        langs=langs,
        timing=dict(timing),
        mode=mode,
        unified_prefix=unified_prefix,
        # audit_config is built internally (above) and uses the internal-only
        # "remove_bracketed" strategy, which is absent from the public
        # VALID_STRATEGIES; opt this trusted pass out of the public-strategy
        # config check. No user-facing path sets this, so "remove_bracketed"
        # stays unselectable from config / strategy_overrides.
        _allow_internal_strategies=True,
    )

    marker = resolve_marker(display_marker)
    display_text = mark_for_display(downstream_text, key, marker=marker)

    # Detection ran once with one seed; the realistic pass emits realistic fakes
    # (or bare PREFIX-NNNNN on pool exhaustion) and the audit pass emits bracketed
    # [PREFIX-NNNNN] placeholders, so the two output spaces are disjoint by
    # construction. _merge_pseudonym_keys enforces that as an invariant rather than
    # trusting it: it raises PseudonymKeyCollisionError if any code maps to two
    # different originals, turning a would-be silent identity splice (the pre-fix
    # blind `{**key, **audit_key}`, where audit silently overwrote a colliding
    # realistic mapping) into a loud failure.
    unified_key = _merge_pseudonym_keys(key, audit_key)
    # fake → SSOT PII type, built PER PASS then merged. In the unified key each
    # original has TWO fakes (realistic + [TYPE-NNNNN] audit), so a single
    # original→fake reverse map would drop one — invert each pass's key
    # separately (the two fake-spaces are disjoint, like unified_key).
    unified_types = {
        **_redact_module._build_type_map(key, entities),
        **_redact_module._build_type_map(audit_key, entities),
    }
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
        types=unified_types,
        # Realistic-only key (pre-union with audit_key, see `unified_key`
        # above) — the exact source for a streaming/multi-call caller's
        # existing_key= threading (see StreamingRedactor._redact_and_merge).
        downstream_key=key,
    )


def _salt_to_bytes(salt: int | bytes | None) -> bytes | None:
    """Coerce user-supplied salt to bytes for ``replace()``.

    Accepts int (coerced to 8-byte big-endian) or bytes (passed through).
    Returns ``None`` only when caller explicitly omitted salt — in which case
    ``_resolve_salt`` will raise rather than silently falling back to ``b""``.
    """
    if salt is None:
        return None
    if isinstance(salt, int):
        signed = salt < 0
        try:
            return salt.to_bytes(8, "big", signed=signed)
        except OverflowError as e:
            # An out-of-range int (e.g. seed >= 2**64) raises OverflowError, an
            # ArithmeticError the CLI's (ValueError, TypeError, FileNotFoundError)
            # net does not catch — surfacing a raw traceback. Re-raise as a
            # ValueError with a PII-free message so callers get a clean error.
            raise ValueError(
                "salt out of range: an integer salt must fit in 8 bytes (64-bit)"
            ) from e
    if isinstance(salt, (bytes, bytearray)):
        return bytes(salt)
    raise TypeError(f"salt must be int, bytes, or None, got {type(salt).__name__}")
