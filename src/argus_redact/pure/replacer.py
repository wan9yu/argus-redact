"""replace() — convert pattern matches to redacted text + key."""

from __future__ import annotations

import functools
import warnings
from collections.abc import Mapping
from typing import Callable

from argus_redact._core_loader import _core
from argus_redact._types import PatternMatch, to_rust_pm
from argus_redact.exceptions import SecurityWarning  # noqa: F401
from argus_redact.lang.zh.hints import KINSHIP as _ZH_KINSHIP
from argus_redact.pure._strategy_kind import (
    VALID_STRATEGIES,
    is_strategy_reversible,
)
from argus_redact.pure.grammar import SELF_REF_PRONOUNS, normalize_grammar_en
from argus_redact.pure.security_events import (
    ALIAS_COLLISION,
    COVERAGE_RESTORED,
    KEEP_DOWNGRADED,
    MASK_COLLISION,
    _auto_stacklevel,
    security_event,
)

# Strategy-classification SSOT lives in the dependency-free `_strategy_kind`
# leaf and is re-exported here for back-compat (public `argus_redact.
# is_strategy_reversible` resolves through this module). `VALID_STRATEGIES` /
# `is_strategy_reversible` are imported above, not defined here, so registry can
# import the leaf top-level without a cycle.
__all__ = [
    "VALID_STRATEGIES",
    "is_strategy_reversible",
    "SecurityWarning",
    "replace",
    "warn_mask_collisions",
    "warn_alias_collisions",
]


# ``keep`` strategy preserves these verbatim; anything else downgrades to the
# type's default with SecurityWarning. Guards against H6 where Layer-3 could
# misclassify sensitive PII (e.g. SSN strings) as ``self_reference``.
# Sources: en pronouns from grammar.SELF_REF_PRONOUNS; zh kinship from the
# same SSOT consumed by hints.kinship_tier (no parallel list to drift).
_ZH_PRONOUNS = frozenset({"我", "我的", "我们", "我们的"})
_KEEP_WHITELIST = SELF_REF_PRONOUNS | _ZH_PRONOUNS | _ZH_KINSHIP


def _registry_generation() -> int:
    """Read the registry's current generation counter.

    Part of every faker-cache key. ``register()``/``unregister()`` bump it
    BEFORE clearing the caches, so a resolve that was already in flight —
    having computed its result against the pre-mutation registry — inserts
    under the OLD generation. That entry is then dead: no later call ever
    reads it, because every later call keys on the new generation.

    Clear-after-write alone cannot give that guarantee: ``lru_cache`` has no
    lock the writer can take, so the in-flight resolve's insert lands AFTER
    ``cache_clear()`` and the stale value survives for the life of the
    process (a custom ``faker_reserved`` permanently shadowed by a ``None``
    computed microseconds too early). Read lazily to avoid the
    registry -> replacer import cycle.
    """
    from argus_redact.specs import registry

    return registry.generation()


def _resolve_default_strategy(entity_type: str, langs: list[str] | None = None) -> str:
    """Look up the type's declared strategy from the typedef registry.

    v0.6.8: single source of truth = specs/{zh,en,shared}.py PIITypeDef.strategy.

    v0.8.10: lang-aware. When the same type NAME is registered under more than
    one language, prefer the typedef for one of the entity's detected `langs`
    (in order), then 'shared', then whichever typedef happens to be first (the
    old lang-blind behaviour) as a last resort — the SAME preference order
    `_resolve_realistic_faker` already uses for the realistic-faker lookup. No
    currently-registered type disagrees on `strategy` across languages, so this
    is a forward-looking correctness fix (dormant today), not an observed bug.
    """
    # Lazy import to avoid circular: registry imports types, types reference replacer
    from argus_redact.specs.registry import lookup

    typedef_list = lookup(entity_type)
    if not typedef_list:
        return "remove"  # fallback for unknown types
    by_lang = {td.lang: td for td in typedef_list}
    for lang in langs or ():
        if lang in by_lang:
            return by_lang[lang].strategy
    if "shared" in by_lang:
        return by_lang["shared"].strategy
    return typedef_list[0].strategy


def _resolved_strategy(entity_type: str, config: dict | None) -> str:
    """The strategy that applies to ``entity_type`` — explicit config over the
    registry default. Single source for keep-downgrade + residual-PII.

    Intentionally lang-blind: this only decides whether the effective strategy
    is ``keep`` (the self_reference/kinship whitelist check), not which
    replacement fires, and no caller here has a detected-langs list in scope.
    The lang-aware resolution lives in ``_build_type_info``, the path that
    actually determines the applied redaction strategy.
    """
    ec = _get_entity_config(entity_type, config)
    return ec.get("strategy") or _resolve_default_strategy(entity_type)


def _keep_downgraded_entities(entities, config: dict | None):
    """Entities whose ``keep`` strategy is downgraded — ``keep`` is only valid for
    whitelisted self_reference pronouns/kinship. Deduped by text. THE predicate
    shared by the SecurityWarning path and the security_event path (no drift)."""
    out, seen = [], set()
    for e in entities:
        if e.text in seen:
            continue
        if _resolved_strategy(e.type, config) != "keep":
            continue
        if e.type == "self_reference" and e.text in _KEEP_WHITELIST:
            continue
        seen.add(e.text)
        out.append(e)
    return out


def _types_event(reason_code: str, count: int, types) -> dict:
    """Build a PII-free security_event whose detail names entity TYPES only.

    THE single source of the ``"types: a, b"`` detail convention, shared by
    every redact-side builder below. That string is what reaches the PII-free
    audit ledger, so it must never carry a raw or masked value — keeping one
    formatter means a change to the convention cannot land in some builders and
    not others.
    """
    detail = "types: " + ", ".join(sorted(set(types)))
    return security_event(reason_code, count=count, detail=detail)


def keep_downgraded_event(entities, config: dict | None) -> dict | None:
    """A PII-free KEEP_DOWNGRADED security_event, or None if nothing downgraded.
    count = unique downgraded entity texts; detail names the TYPES only (never raw
    text) so the event is safe for the PII-free audit ledger."""
    ents = _keep_downgraded_entities(entities, config)
    if not ents:
        return None
    return _types_event(KEEP_DOWNGRADED, len(ents), (e.type for e in ents))


def warn_keep_downgraded(entities, config: dict | None) -> None:
    """Emit the ``keep_downgraded`` SecurityWarning once per downgraded entity —
    a no-op when nothing downgraded. THE single source for that warning's
    text/category/stacklevel, shared by the one-shot ``replace()`` path and the
    structured (``redact_csv``/``redact_json``) ``replace_into_session`` path, so
    the two can never drift apart. Entity SELECTION is single-sourced through
    ``_keep_downgraded_entities`` (the SAME predicate the structured
    ``keep_downgraded_event`` uses).

    The offending text is, by construction, an un-redacted identifier — the whole
    reason this warning fires. Naming the TYPE only keeps the warning stream
    PII-free, matching its sibling ``keep_downgraded_event`` (which emits
    detail="types: ...") and the log-scrub discipline in
    tests/safety/test_layer3_log_scrub.py. Use redact(detailed=True) ->
    security_events for the structured signal.
    """
    for entity in _keep_downgraded_entities(entities, config):
        warnings.warn(
            f"strategy='keep' is only supported for self_reference "
            f"pronouns and kinship phrases; downgrading to default for "
            f"type={entity.type!r}.",
            SecurityWarning,
            stacklevel=_auto_stacklevel(),  # see warn_mask_collisions
        )


def mask_collision_event(mask_collisions: list[str]) -> dict | None:
    """A PII-free MASK_COLLISION security_event, or None if no mask-family
    collision was disambiguated this call. ``mask_collisions`` is the Rust
    core's authoritative list (one entry — the entity type — per collision
    `resolve_collision` actually disambiguated; see ``ReplaceResult.
    mask_collisions``). count = number of collided entries; detail names the
    TYPES only (never the raw or masked value) — mirrors ``keep_downgraded_event``."""
    if not mask_collisions:
        return None
    return _types_event(MASK_COLLISION, len(mask_collisions), mask_collisions)


def warn_mask_collisions(mask_collisions: list[str]) -> None:
    """Emit the ``mask_collision`` SecurityWarning — a no-op when the list is
    empty. THE single source for that warning's text/category, shared by the
    one-shot ``replace()`` path and the structured (``redact_json``/
    ``redact_csv``) path, so the two can never drift apart. See
    ``mask_collision_event`` for the sibling structured-channel event."""
    if not mask_collisions:
        return
    warnings.warn(
        f"{len(mask_collisions)} masked value(s) collided; their "
        f"disambiguator (①) is not LLM-durable — restore of an LLM reply "
        f"may misattribute them.",
        SecurityWarning,
        # Auto-detected, like warn_coverage_restored and the restore guard. A
        # hardcoded 2 lands on `replace()`'s own frame — an argus-internal
        # line — which gives the warning ONE __warningregistry__ dedup slot for
        # the whole process under Python's default filters, so every later
        # session/thread/call site silently loses it.
        stacklevel=_auto_stacklevel(),
    )


def coverage_restored_event(restored_types: list[str]) -> dict | None:
    """A PII-free COVERAGE_RESTORED security_event, or None if the post-merge
    coverage invariant did not fire this call.

    ``restored_types`` is the Rust core's authoritative list — one entry per
    entity whose coverage a post-merge filter destroyed and the invariant
    re-admitted. count = number of restored entities; detail names the TYPES
    only (never the raw value), mirroring ``mask_collision_event``.
    """
    if not restored_types:
        return None
    return _types_event(COVERAGE_RESTORED, len(restored_types), restored_types)


def warn_coverage_restored(restored_types: list[str]) -> None:
    """Emit the ``coverage_restored`` SecurityWarning — a no-op when the list is
    empty. THE single source for that warning's text/category.

    This exists because the structured event is assembled only inside
    ``if report or detailed:``; the warning is what reaches the default 2-tuple
    caller. A firing means the merge absorbed one entity into another (an
    overlapping span won and the loser's bytes were folded into it), and a
    later filter — a type filter or the self-reference tier — then dropped
    that winning span; the invariant re-admitted the entities it had absorbed
    so they stay redacted. Expected on type-filtered calls (``types=``/
    ``types_exclude=`` legitimately excluding a winner that had absorbed
    something else during merge); rare on an unfiltered call. See
    ``coverage_restored_event`` for the sibling structured channel.

    The stacklevel is auto-detected (``_auto_stacklevel``), same as the restore
    guard's warnings — this function is called directly from every public
    entry point (``redact()``, ``redact_json``/``redact_csv``,
    ``StreamingRedactor.feed``/``flush``, ``redact_pseudonym_llm()``), each at
    a different wrapping depth, and a hardcoded number would attribute the
    warning to one of THIS package's own call sites instead of the caller's.
    """
    if not restored_types:
        return
    types = ", ".join(sorted(set(restored_types)))
    warnings.warn(
        f"{len(restored_types)} entity/entities ({types}) lost redaction coverage "
        f"when a filter removed a span that had absorbed them during the merge; "
        f"they were re-admitted and remain redacted in the output.",
        SecurityWarning,
        stacklevel=_auto_stacklevel(),
    )


def alias_collision_event(alias_collisions: list[str]) -> dict | None:
    """A PII-free ALIAS_COLLISION security_event, or None if no alias collided
    this call. ``alias_collisions`` is the Rust core's authoritative list — one
    entry per LOSING claim (see ``restore_full``'s alias-merge step, core
    ``restore.rs``), so a 3+-way collision on the same alias string pushes it
    more than once. Deduped via ``set()`` before counting so the count reflects
    DISTINCT collided aliases, not raw pushes — detail names how many, never
    the raw alias/original — mirrors ``mask_collision_event``."""
    if not alias_collisions:
        return None
    distinct = set(alias_collisions)
    return security_event(
        ALIAS_COLLISION,
        count=len(distinct),
        detail=f"{len(distinct)} alias(es) collided",
    )


def warn_alias_collisions(alias_collisions: list[str]) -> None:
    """Emit the ``alias_collision`` SecurityWarning — a no-op when the list is
    empty. THE single source for that warning's text/category, called from
    ``pure/restore._do_restore`` wherever the core restore result comes back —
    mirrors ``warn_mask_collisions``. Deduped via ``set()`` before counting —
    see ``alias_collision_event``."""
    if not alias_collisions:
        return
    count = len(set(alias_collisions))
    warnings.warn(
        f"{count} alias(es) map to more than one original; the "
        "restored value for a collided alias may be the wrong identity.",
        SecurityWarning,
        stacklevel=_auto_stacklevel(),  # see warn_mask_collisions
    )


def residual_personal_data(entities) -> bool:
    """True if what ``redact()`` returns still constitutes personal data under
    GDPR Art.4(5) — i.e. the original value is recoverable from the returned
    artifacts, NOT whether the surrogate looks reversible on its face.

    Every strategy in the current palette retains the original one way or
    another: the substituting strategies (pseudonym/realistic/mask/remove/
    category/name_mask/landline_mask) write ``surrogate -> original`` into
    the ``key`` dict ``redact()`` returns, so the surrogate can be mapped
    back even when the strategy is classified "irreversible" for LLM-restore
    purposes (see ``is_strategy_reversible``) — a retained recovery key means
    pseudonymised/masked output is still personal data. ``keep`` needs no key
    at all: it leaves the original value verbatim in the output text.

    So this is True whenever at least one entity was detected, and False
    only when nothing was detected (nothing to recover). Deliberately NOT
    derived from ``is_strategy_reversible`` — that SSOT answers a different
    question (LLM round-trip safety), not GDPR residual-data status.
    """
    return bool(entities)


DEFAULT_PREFIXES = {
    "person": "P",
    "organization": "O",
    # Pseudonym prefixes for remove-as-pseudonym strategy (improves LLM survival rate)
    "id_number": "ID",
    "passport": "PASS",
    "license_plate": "PLATE",
    "address": "ADDR",
    "ssn": "SSN",
    "military_id": "MIL",
    "social_security": "SOC",
    "credit_code": "BIZ",
    "date_of_birth": "DOB",
    "us_passport": "PASS",
    "job_title": "TITLE",
    "school": "SCH",
    "ethnicity": "ETH",
    "workplace": "WORK",
    "hobby": "HOBBY",
    "criminal_record": "CRIM",
    "financial": "FIN",
    "biometric": "BIO",
    "medical": "MED",
    "religion": "REL",
    "political": "POL",
    "sexual_orientation": "ORI",
    "ip_address": "IP",
    "mac_address": "MAC",
    "imei": "IMEI",
    "url_token": "URL",
    "age": "AGE",
    "gender": "GEN",
    "self_reference": "S",
    # Quasi-identifiers referenced by integrations (Presidio, profiles)
    "phone_landline": "LL",
    "date": "DATE",
    "url": "URL",
    # Credentials / secrets
    "openai_api_key": "OAI-KEY",
    "anthropic_api_key": "ANT-KEY",
    "aws_access_key": "AWS-KEY",
    "github_token": "GH-TOKEN",
    "jwt": "JWT",
    "ssh_private_key": "SSH-KEY",
}

# Default label for category strategy
DEFAULT_CATEGORY_LABEL = {
    "location": "[LOCATION]",
}


def _get_entity_config(
    entity_type: str,
    config: dict | None,
) -> dict:
    """Get merged config for an entity type: user config over defaults."""
    if config and entity_type in config:
        return config[entity_type]
    return {}


def _validate_config(config: dict | None) -> None:
    """Validate user config, raise ValueError on invalid strategy."""
    if not config:
        return
    if not isinstance(config, Mapping):
        raise TypeError(
            f"config must be a dict mapping entity type to settings, got {type(config).__name__}"
        )
    for entity_type, type_config in config.items():
        # `_unified_prefix` is the one reserved sentinel key (removed in
        # v0.6.0); it carries a scalar value and is validated/rejected by its
        # own dedicated check in replace(). Skip it here so this per-type dict
        # check doesn't shadow that rejection. Other underscore-named keys are
        # ordinary custom entity types (register_pii_type permits them) and
        # must go through the same strategy validation as any other type.
        if entity_type == "_unified_prefix":
            continue
        if not isinstance(type_config, dict):
            raise TypeError(
                f"config[{entity_type!r}] must be a dict, got {type(type_config).__name__}"
            )
        strategy = type_config.get("strategy")
        if strategy and strategy not in VALID_STRATEGIES:
            raise ValueError(
                f"Unknown strategy '{strategy}' for entity type "
                f"'{entity_type}'. Valid: {', '.join(VALID_STRATEGIES)}"
            )


def _mask_phone_regional(value: str, *, region: str = "cn") -> str:
    """Phone mask with regional rules.

    cn (mainland): 137****5678 (3+4+4)
    hk (Hong Kong): 90****56 (2+4+2)
    tw (Taiwan): 90****567 (2+4+3)
    default: first 2 + **** + last 2
    """
    digits = value.replace("-", "").replace(" ", "")

    if region == "cn" or (region == "auto" and len(digits) == 11):
        p, s = 3, 4
    elif region == "hk" or (region == "auto" and len(digits) == 8):
        p, s = 2, 2
    elif region == "tw" or (region == "auto" and len(digits) == 9):
        p, s = 2, 3
    else:
        p, s = 2, 2

    if len(digits) <= p + s:
        return "*" * len(digits)
    masked_len = len(digits) - p - s
    return digits[:p] + "*" * masked_len + digits[-s:]


def _resolve_realistic_faker(
    name: str, langs: list[str] | None
) -> tuple[str, str | Callable] | None:
    """Unified lang-preference resolution for the ``realistic`` strategy.

    Returns ``("builtin", faker_name)`` / ``("custom", callable)`` / ``None``.

    Bit-identity critical: built-ins (callable-less, resolved via the Rust
    ``_core`` association) and custom ``faker_reserved`` callables compete in a
    single lang-preference pass (detected langs → 'shared' → any registered,
    each in registry order). The
    first candidate lang that has EITHER a built-in association OR a custom
    callable wins — so a built-in for the detected lang is never shadowed by a
    custom faker registered for a different lang (the #1 wrong-language risk).
    """
    return _resolve_realistic_faker_cached(name, tuple(langs or ()), _registry_generation())


@functools.lru_cache(maxsize=256)
def _resolve_realistic_faker_cached(
    name: str, langs: tuple[str, ...], _generation: int
) -> tuple[str, str | Callable] | None:
    from argus_redact.specs.registry import lookup

    by_lang = {td.lang: td for td in lookup(name)}

    def _for_lang(lang: str) -> tuple[str, str | Callable] | None:
        # A registered custom callable for this lang wins (it OVERRODE the
        # typedef); the built-in `_core` association is the callable-less
        # fallback when the typedef carries no custom faker.
        td = by_lang.get(lang)
        if td is not None and td.faker_reserved is not None:
            return ("custom", td.faker_reserved)
        builtin = _core.builtin_faker_name(name, lang)
        if builtin is not None:
            return ("builtin", builtin)
        return None

    # 1. detected langs, in caller order
    for lang in langs:
        hit = _for_lang(lang)
        if hit is not None:
            return hit
    # 2. cross-language 'shared' fallback
    hit = _for_lang("shared")
    if hit is not None:
        return hit
    # 3. any registered lang, in registry order (mirrors by_lang.values())
    for td in by_lang.values():
        hit = _for_lang(td.lang)
        if hit is not None:
            return hit
    return None


# The single cache-invalidation entry point for the realistic faker resolver;
# register()/unregister() call it.
def _clear_faker_caches() -> None:
    _resolve_realistic_faker_cached.cache_clear()


def _build_type_info(
    entities: list[PatternMatch],
    config: dict | None,
    langs: list[str] | None,
    *,
    rust_entities: list | None = None,
) -> tuple[dict[str, dict], dict[str, Callable]]:
    """Resolve the per-type replacement info the Rust ``replace`` needs, plus any
    custom Python ``faker_reserved`` callables to pass as the Rust callback map.

    For every entity type present, folds the registry default + user config +
    ``DEFAULT_PREFIXES`` / ``DEFAULT_CATEGORY_LABEL`` + the built-in faker name
    into a flat dict matching the Rust ``TypeInfo`` struct. The faker is resolved
    once per type and reused for both the ``faker_name`` field and the custom-faker
    detection.

    Returns ``(info, custom_fakers)`` where ``custom_fakers`` maps each type whose
    effective strategy is ``realistic`` and whose ``faker_reserved`` callable is NOT
    a built-in (i.e. has no ``_core.builtin_faker_name(type, lang)`` association) to
    that callable. The Rust core receives this map and invokes the callable via
    ``PyFakerFactory`` when ``TypeInfo.custom_faker`` is true. Built-in realistic
    fakers resolve in Rust by name; types with no faker fall through to a pseudonym.

    SSOT: the ``info`` dict assembly (default strategy + user config + prefix /
    category label + the built-in faker name) lives in the Rust core
    (``_core.build_type_info``) so the PyO3 binding and a future wasm crate share
    one implementation.

    The per-type DEFAULTS, however, are owned by the Python registry — it is the
    only place a runtime adapter type (``register_pii_type(...)``) is visible, and
    the Rust core's built-in tables can't see it. So we resolve the authoritative
    default strategy / prefix / category-label per detected type here (from
    ``_resolve_default_strategy`` + ``DEFAULT_PREFIXES`` / ``DEFAULT_CATEGORY_LABEL``,
    exactly as the pre-port Python did) and thread them into the core as
    ``registry_defaults``; the core uses them when present and falls back to its
    built-in tables only on the wasm path (no Python registry).

    The other Python-only piece is the custom-adapter faker overlay: a type
    registered with ``faker_reserved=…`` carries a Python callable the core can't
    see, so we re-run the lang-preference resolver here and, when it picks a
    CUSTOM callable (which may legitimately shadow a built-in for another lang),
    flip the core's ``faker_name``/``custom_faker`` fields and collect the callable.
    """
    # Built-in assembly in Rust (single SSOT). `custom_faker` is always False here.
    # The core reads only `entity.type` off the Rust PatternMatch the binding
    # expects. `replace()` / `replace_into_session()` already marshal that list for
    # their own `_core.replace` / `session.redact_cell` call, so they thread it in
    # here (`rust_entities=`) to avoid building the identical list twice per call —
    # paid per cell on redact_csv / redact_json. A standalone caller omits it and
    # one is built here (same idiom as `replace()` / merger).
    if rust_entities is None:
        rust_entities = [to_rust_pm(e) for e in entities]
    # Per-type defaults from the live registry (SSOT; includes runtime adapter
    # types). Resolve once per distinct detected type — the same lookups the
    # pre-port `_build_type_info` did inline (strategy from the registry, prefix /
    # label from the module-level DEFAULT_* maps). The core uses these and only
    # falls back to its built-in tables for types absent from this map (wasm).
    registry_defaults: dict[str, dict] = {}
    for e in entities:
        if e.type in registry_defaults:
            continue
        registry_defaults[e.type] = {
            "strategy": _resolve_default_strategy(e.type, langs),
            "prefix": DEFAULT_PREFIXES.get(e.type, e.type.upper()[:4]),
            "category_label": DEFAULT_CATEGORY_LABEL.get(e.type, f"[{e.type}]"),
        }
    info: dict[str, dict] = _core.build_type_info(rust_entities, config, langs, registry_defaults)

    # Custom-adapter faker overlay (the only Python-side piece). For every
    # realistic type, re-run the SAME single lang-preference pass the built-in
    # resolver used: when it resolves to a CUSTOM callable, that callable WON the
    # precedence (it can shadow a built-in for another lang), so flip the core's
    # fields and route it through the Rust callback. A built-in / no-faker result
    # leaves the core's `faker_name` untouched.
    custom_fakers: dict[str, Callable] = {}
    for etype, ti in info.items():
        if ti["strategy"] != "realistic":
            continue
        resolved = _resolve_realistic_faker(etype, langs)
        if resolved is not None and resolved[0] == "custom":
            ti["faker_name"] = None
            ti["custom_faker"] = True
            custom_fakers[etype] = resolved[1]
    return info, custom_fakers


def replace(
    text: str,
    entities: list[PatternMatch],
    *,
    salt: int | bytes | None = None,
    key: dict[str, str] | None = None,
    config: dict | None = None,
    langs: list[str] | None = None,
    unified_prefix: str | None = None,
    _mask_collisions: list[str] | None = None,
) -> tuple[str, dict[str, str], dict[str, list[str]]]:
    """Replace detected entities in text, producing ``(redacted_text, key, aliases)``.

    Single-pass orchestrator. The whole pass runs in Rust (``_core.replace``);
    a **custom** Python ``faker_reserved`` (realistic strategy) is invoked
    mid-loop via the Rust ``PyFakerFactory`` callback, so the redact path is the
    same regardless of whether built-in or custom fakers fire.

    config overrides default strategies per entity type. Example:
        {"phone": {"strategy": "remove", "replacement": "[TEL]"}}

    `langs` provides language preference for the realistic strategy's
    faker_reserved lookup (e.g., en text prefers en/phone over zh/phone).

    `unified_prefix` (v0.6.0+): if provided, all reversible-strategy types
    collapse to a single ``<prefix>-NNNNN`` form, hiding PII type information
    from the output. Replaces the legacy ``config["_unified_prefix"]`` sentinel.

    Returns ``(redacted_text, key, aliases)`` where ``aliases`` is
    ``{fake: list_of_aliases}`` for entries whose realistic-strategy fakers
    emitted aliases (empty dict when no realistic-strategy fakers ran).

    ``_mask_collisions`` is internal: when given a list, it is MUTATED in
    place (appended to, never replaced) with one entry per mask-family
    collision this call disambiguated — mirroring the ``timing`` dict
    out-param idiom in ``glue/redact.py``. ``glue._replace_and_emit`` uses it
    to build the structured ``mask_collision`` security_event without
    widening this function's public 3-tuple return.
    """
    # Validate + reject the removed _unified_prefix sentinel up front so both
    # paths raise identically (the Rust path would otherwise silently accept it).
    _validate_config(config)
    if config and "_unified_prefix" in config:
        raise ValueError(
            "_unified_prefix is no longer accepted as a config key in v0.6.0. "
            "Use the top-level `unified_prefix=` kwarg on redact() / "
            "redact_pseudonym_llm() instead."
        )

    # Convert the dataclass entities into the Rust PatternMatch the binding
    # expects (via the shared `to_rust_pm` seam, same as pure/merger.py). Built
    # ONCE here and threaded into `_build_type_info` so the identical list is not
    # rebuilt inside it as well.
    rust_entities = [to_rust_pm(e) for e in entities]

    # Build the per-type info once; the custom_fakers dict is passed to _core.replace
    # so Rust can invoke Python callables via PyFakerFactory. The Rust core is
    # required (lang/_loader raises ImportError without it); replace() always runs
    # in Rust and the historical pure-Python orchestrator has been removed.
    type_info, custom_fakers = _build_type_info(
        entities, config, langs, rust_entities=rust_entities
    )

    # Person / organization pseudonym prefixes (config can override) — via the
    # SSOT so this one-shot path and the structured session builder never drift.
    person_prefix, org_prefix = _resolve_person_org_prefixes(config)

    redacted, result_key, aliases, signals = _core.replace(
        text,
        rust_entities,
        salt=salt,
        key=key,
        type_info=type_info,
        person_prefix=person_prefix,
        org_prefix=org_prefix,
        unified_prefix=unified_prefix,
        keep_whitelist=_KEEP_WHITELIST,
        custom_fakers=custom_fakers if custom_fakers else None,
    )
    keep_downgraded = signals["keep_downgraded"]
    mask_collisions = signals["mask_collisions"]

    # `keep_downgraded` is the Rust core's authoritative "a downgrade happened"
    # signal. The Python-side entity SELECTION (which entities to warn about, and
    # the structured keep_downgraded security_event built in glue) is single-sourced
    # through `_keep_downgraded_entities` — so the warning here and the event in
    # `keep_downgraded_event` cannot drift from each other. If the Rust whitelist
    # logic (`keep_whitelist=`) ever changes, update `_keep_downgraded_entities` too.
    if keep_downgraded:
        warn_keep_downgraded(entities, config)

    # `mask_collisions`: the Rust core disambiguated a mask-family
    # collision (two different originals wanting the same visible label) with a
    # trailing circled-digit suffix. The collided entry STAYS in `result_key` (a
    # direct in-process restore still works) — but that disambiguator is fragile
    # against an LLM that normalizes it away, so warn that an LLM-round-trip
    # restore of the collided entry may misattribute it. Mirrors the
    # `keep_downgraded` plumbing above: Rust is the sole authority on whether a
    # real collision happened (unlike keep_downgraded, this can't be re-derived
    # from `entities`/`config` alone — it depends on collision-resolution order).
    if _mask_collisions is not None:
        _mask_collisions.extend(mask_collisions)
    warn_mask_collisions(mask_collisions)

    return redacted, result_key, aliases


def _resolve_person_org_prefixes(config: dict | None) -> tuple[str, str]:
    """Resolve the (person, organization) pseudonym prefixes — config override
    else ``DEFAULT_PREFIXES``. Single source shared by ``replace`` and the
    structured session builder so the two never drift."""
    person_prefix = DEFAULT_PREFIXES["person"]
    org_prefix = DEFAULT_PREFIXES["organization"]
    if config:
        person_prefix = config.get("person", {}).get("prefix", person_prefix)
        org_prefix = config.get("organization", {}).get("prefix", org_prefix)
    return person_prefix, org_prefix


def make_structured_session(
    *,
    salt: int | bytes | None = None,
    key: dict[str, str] | None = None,
    config: dict | None = None,
    unified_prefix: str | None = None,
):
    """Build a stateful ``_core.StructuredRedactor`` for a whole structured
    document (CSV / JSON), so redacting its N cells keeps the accumulation key +
    pseudonym generators in Rust and stays O(N) instead of O(N²).

    The salt / prefixes / keep-whitelist are constant for the document (they come
    from the one ``redact_csv`` / ``redact_json`` call), so they are fixed at
    construction; per-cell entities + type_info are fed via ``replace_into_session``.
    Validates ``config`` and rejects the removed ``_unified_prefix`` sentinel
    identically to ``replace`` (so both paths raise the same way).
    """
    _validate_config(config)
    if config and "_unified_prefix" in config:
        raise ValueError(
            "_unified_prefix is no longer accepted as a config key in v0.6.0. "
            "Use the top-level `unified_prefix=` kwarg on redact() / "
            "redact_pseudonym_llm() instead."
        )
    person_prefix, org_prefix = _resolve_person_org_prefixes(config)
    return _core.StructuredRedactor(
        salt=salt,
        key=key,
        person_prefix=person_prefix,
        org_prefix=org_prefix,
        unified_prefix=unified_prefix,
        keep_whitelist=_KEEP_WHITELIST,
    )


def replace_into_session(
    session,
    text: str,
    entities: list[PatternMatch],
    *,
    config: dict | None = None,
    langs: list[str] | None = None,
) -> str:
    """Redact one cell/leaf through a ``make_structured_session`` session, returning
    its redacted text. The accumulation key + generators live in the session (read
    once at the end via ``session.into_key()``).

    Byte-identical to a per-cell ``replace(...)`` call that threads the growing key
    back in: it builds the SAME per-type info + custom fakers, drives the SAME core
    replace engine, emits the SAME per-cell ``keep``-downgrade warnings, and applies
    the SAME English grammar normalization — only the key stays in Rust across cells.
    """
    # Marshal the dataclass entities once and thread the same list into
    # `_build_type_info` so it is not rebuilt there as well (paid per cell).
    rust_entities = [to_rust_pm(e) for e in entities]
    type_info, custom_fakers = _build_type_info(
        entities, config, langs, rust_entities=rust_entities
    )
    redacted = session.redact_cell(
        text, rust_entities, type_info, custom_fakers if custom_fakers else None
    )

    # Same per-cell keep-downgrade warning selection as `replace` (single-sourced
    # through `warn_keep_downgraded` -> `_keep_downgraded_entities`); the session's
    # cumulative flag is a cross-check, not the per-cell signal.
    warn_keep_downgraded(entities, config)

    # English article/grammar fix-up, exactly as `_replace_and_emit`. Normalize
    # against THIS cell's own originals only — the cumulative key's extras are not
    # present in this cell's text and so are no-ops, and calling session.into_key()
    # per cell would re-clone and marshal the whole growing key across PyO3, which
    # is exactly the O(N^2) blow-up the Rust session exists to avoid. zh (the common
    # structured path) skips this entirely.
    effective_lang = langs[0] if langs else "zh"
    if effective_lang == "en":
        redacted = normalize_grammar_en(redacted, [e.text for e in entities])
    return redacted
