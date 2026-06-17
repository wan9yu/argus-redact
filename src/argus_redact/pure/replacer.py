"""replace() — convert pattern matches to redacted text + key."""

from __future__ import annotations

import functools
import warnings
from typing import Callable

from argus_redact._core_loader import _core, HAS_CORE
from argus_redact._types import PatternMatch
from argus_redact.lang.zh.hints import KINSHIP as _ZH_KINSHIP
from argus_redact.pure.grammar import SELF_REF_PRONOUNS

# Rust PatternMatch class, resolved once at import (same idiom as pure/merger.py).
# The Rust core is mandatory; HAS_CORE is kept for the ternary guard only so the
# module doesn't crash at import time when _core is absent (broken install).
_RustPM = _core.PatternMatch if HAS_CORE else None


class SecurityWarning(UserWarning):
    """Emitted when a misconfiguration would silently weaken redaction."""


VALID_STRATEGIES = (
    "pseudonym",
    "realistic",
    "mask",
    "remove",
    "category",
    "name_mask",
    "landline_mask",
    "keep",
)

# Strategies whose output can be mapped back to the original via the key dict.
# Adding a new strategy to VALID_STRATEGIES requires classifying it here.
_REVERSIBLE_STRATEGIES = frozenset({"pseudonym", "realistic", "remove", "keep"})


def is_strategy_reversible(strategy: str) -> bool:
    """Return True if ``strategy`` produces output that ``restore()`` can map
    back to the original value.

    Reversible: ``pseudonym`` / ``realistic`` / ``remove`` / ``keep``.
    Irreversible (lossy by design): ``mask`` / ``name_mask`` / ``landline_mask``
    / ``category``.

    Use in multi-turn dialog flows to fall through to a reversible strategy
    when the LLM response must be restored to original PII for follow-up.
    """
    if strategy not in VALID_STRATEGIES:
        raise ValueError(
            f"Unknown strategy '{strategy}'. Valid: {', '.join(VALID_STRATEGIES)}"
        )
    return strategy in _REVERSIBLE_STRATEGIES


# ``keep`` strategy preserves these verbatim; anything else downgrades to the
# type's default with SecurityWarning. Guards against H6 where Layer-3 could
# misclassify sensitive PII (e.g. SSN strings) as ``self_reference``.
# Sources: en pronouns from grammar.SELF_REF_PRONOUNS; zh kinship from the
# same SSOT consumed by hints.kinship_tier (no parallel list to drift).
_ZH_PRONOUNS = frozenset({"我", "我的", "我们", "我们的"})
_KEEP_WHITELIST = SELF_REF_PRONOUNS | _ZH_PRONOUNS | _ZH_KINSHIP


def _find_faker_reserved(name: str, langs: list[str] | None) -> Callable | None:
    """Find faker_reserved for a type, preferring detected langs, then 'shared', then any.

    Lang-aware lookup is required when zh and en both register same-named types
    (e.g., `phone`, `address`, `person`); without preference order, the first
    registered lang silently wins regardless of the entity's actual language.

    Cached on (name, lang_tuple) — registry is built at import and frozen.
    """
    return _faker_reserved_cached(name, tuple(langs or ()))


@functools.lru_cache(maxsize=256)
def _faker_reserved_cached(name: str, langs: tuple[str, ...]) -> Callable | None:
    from argus_redact.specs.registry import lookup

    by_lang = {td.lang: td for td in lookup(name)}
    for lang in langs:
        if lang in by_lang and by_lang[lang].faker_reserved:
            return by_lang[lang].faker_reserved
    if "shared" in by_lang and by_lang["shared"].faker_reserved:
        return by_lang["shared"].faker_reserved
    for td in by_lang.values():
        if td.faker_reserved:
            return td.faker_reserved
    return None


def _resolve_default_strategy(entity_type: str) -> str:
    """Look up the type's declared strategy from the typedef registry.

    v0.6.8: single source of truth = specs/{zh,en,shared}.py PIITypeDef.strategy.
    """
    # Lazy import to avoid circular: registry imports types, types reference replacer
    from argus_redact.specs.registry import lookup
    typedef_list = lookup(entity_type)
    if typedef_list:
        return typedef_list[0].strategy
    return "remove"  # fallback for unknown types


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
    for entity_type, type_config in config.items():
        if not isinstance(type_config, dict):
            continue
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


@functools.lru_cache(maxsize=1)
def _builtin_faker_names() -> frozenset[str]:
    """Function names of the built-in reserved-range fakers.

    These resolve in the Rust core's by-function-name faker dispatch
    (``_core.resolve_faker``). Computed by introspecting the four built-in faker
    modules so a newly-added built-in is auto-discovered (no parallel list to
    drift). A custom ``register_pii_type(faker_reserved=...)`` callable lives in
    a different module, so its ``__name__`` is absent here → it is flagged as a
    custom faker and invoked via the Rust ``PyFakerFactory`` callback. Matches
    the Rust ``resolve_faker`` key set exactly.
    """
    import inspect

    from argus_redact.specs import (
        fakers_en_reserved,
        fakers_numeric,
        fakers_shared_reserved,
        fakers_zh_reserved,
    )

    names: set[str] = set()
    for mod in (
        fakers_zh_reserved,
        fakers_en_reserved,
        fakers_shared_reserved,
        fakers_numeric,
    ):
        for nm, obj in vars(mod).items():
            if (
                inspect.isfunction(obj)
                and obj.__module__ == mod.__name__
                and nm.startswith("fake_")
            ):
                names.add(nm)
    return frozenset(names)


def _build_type_info(
    entities: list[PatternMatch],
    config: dict | None,
    langs: list[str] | None,
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
    a built-in (i.e. not resolvable by Rust's by-function-name faker dispatch) to
    that callable. The Rust core receives this map and invokes the callable via
    ``PyFakerFactory`` when ``TypeInfo.custom_faker`` is true. Built-in realistic
    fakers resolve in Rust by name; types with no faker fall through to a pseudonym.
    """
    info: dict[str, dict] = {}
    custom_fakers: dict[str, Callable] = {}
    builtin_names = _builtin_faker_names()
    for entity in entities:
        etype = entity.type
        if etype in info:
            continue
        ec = _get_entity_config(etype, config)
        default_strategy = _resolve_default_strategy(etype)
        strategy = ec.get("strategy") or default_strategy
        prefix_overridden = "prefix" in ec
        prefix = ec.get("prefix", DEFAULT_PREFIXES.get(etype, etype.upper()[:4]))

        # Resolve the faker once; derive both the built-in name (for Rust) and the
        # custom-faker flag (for dispatch). A non-realistic type needs neither.
        faker_name = None
        is_custom_faker = False
        if strategy == "realistic":
            faker = _find_faker_reserved(etype, langs)
            if faker is not None:
                name = getattr(faker, "__name__", None)
                if name in builtin_names:
                    faker_name = name
                else:
                    is_custom_faker = True  # custom faker → Rust callback
                    custom_fakers[etype] = faker

        info[etype] = {
            "strategy": strategy,
            "default_strategy": default_strategy,
            "prefix": prefix,
            "prefix_overridden": prefix_overridden,
            "faker_name": faker_name,
            "custom_faker": is_custom_faker,
            "replacement": ec.get("replacement"),
            "label": ec.get("label"),
            "default_category_label": DEFAULT_CATEGORY_LABEL.get(etype, f"[{etype}]"),
            "visible_prefix": int(ec.get("visible_prefix", 0) or 0),
            "visible_suffix": int(ec.get("visible_suffix", 0) or 0),
        }
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

    # Build the per-type info once; the custom_fakers dict is passed to _core.replace
    # so Rust can invoke Python callables via PyFakerFactory. The Rust core is
    # required (lang/_loader raises ImportError without it); replace() always runs
    # in Rust and the historical pure-Python orchestrator has been removed.
    type_info, custom_fakers = _build_type_info(entities, config, langs)

    # Person / organization pseudonym prefixes (config can override).
    person_prefix = DEFAULT_PREFIXES["person"]
    org_prefix = DEFAULT_PREFIXES["organization"]
    if config:
        person_prefix = config.get("person", {}).get("prefix", person_prefix)
        org_prefix = config.get("organization", {}).get("prefix", org_prefix)

    # Convert the dataclass entities into the Rust PatternMatch the binding
    # expects (same idiom as pure/merger.py). `_RustPM` is resolved at import.
    rust_entities = [
        _RustPM(e.text, e.type, e.start, e.end, e.confidence, e.layer)
        for e in entities
    ]

    redacted, result_key, aliases, keep_downgraded = _core.replace(
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

    if keep_downgraded:
        # Mirror the Python path's per-entity SecurityWarning. The Rust core
        # only signals THAT a downgrade happened; reconstruct the per-entity
        # messages here so the warning surface is unchanged. The Python loop
        # processes each distinct entity.text once (dedup via entity_replacements
        # / reverse_index), warning only on a keep entity that is NOT a
        # whitelisted self_reference. We replay that same dedup + guard.
        warned: set[str] = set()
        for entity in entities:
            if entity.text in warned:
                continue
            ec = _get_entity_config(entity.type, config)
            strategy = ec.get("strategy") or _resolve_default_strategy(entity.type)
            if strategy != "keep":
                continue
            warned.add(entity.text)
            if entity.type == "self_reference" and entity.text in _KEEP_WHITELIST:
                continue  # whitelisted → kept verbatim, no warning
            warnings.warn(
                f"strategy='keep' is only supported for self_reference "
                f"pronouns and kinship phrases; downgrading to default for "
                f"type={entity.type!r}, text={entity.text[:40]!r}.",
                SecurityWarning,
                stacklevel=2,
            )

    return redacted, result_key, aliases
