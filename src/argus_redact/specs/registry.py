"""PII type registry — central definition of all PII types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class PIITypeDef:
    """Complete definition of a PII type."""

    # ── Identity ──
    name: str                                       # "phone", "id_number"
    lang: str                                       # "zh", "en", "shared"

    # ── Structure ──
    format: str                                     # "1[3-9]XXXXXXXXX"
    length: int | tuple[int, int] | None = None     # 11 or (16, 19)
    charset: str = "digits"                         # "digits", "digits+X", "alnum"
    structure: dict[str, str] = field(default_factory=dict)  # segment descriptions

    # ── Validation ──
    checksum: str | None = None                     # "MOD11-2", "Luhn", None
    validate: Callable[[str], bool] | None = None   # runtime validator

    # ── Context ──
    prefixes: tuple[str, ...] = ()                  # context words before PII
    suffixes: tuple[str, ...] = ()                  # context words after PII
    separators: tuple[str, ...] = ("",)             # allowed in-value separators

    # ── Action ──
    strategy: str = "remove"                        # "mask", "pseudonym", "remove", "category"
    label: str = ""                                 # "[手机号已脱敏]"
    mask_rule: dict[str, int] | None = None         # {"visible_prefix": 3, "visible_suffix": 4}

    # ── Evidence ──
    examples: tuple[str, ...] = ()                  # valid instances
    counterexamples: tuple[str, ...] = ()           # should NOT match
    source: str = ""                                # authoritative reference

    # ── Description ──
    description: str = ""


# ── Global registry ──

_REGISTRY: dict[tuple[str, str], PIITypeDef] = {}


def register(typedef: PIITypeDef) -> PIITypeDef:
    """Register a PII type definition."""
    key = (typedef.lang, typedef.name)
    _REGISTRY[key] = typedef
    return typedef


def get(lang: str, name: str) -> PIITypeDef:
    """Get a PII type definition by language and name."""
    key = (lang, name)
    if key not in _REGISTRY:
        raise KeyError(f"No PII type '{name}' for lang '{lang}'")
    return _REGISTRY[key]


def lookup(name: str) -> list[PIITypeDef]:
    """Find all definitions for a PII type across languages."""
    return [v for (_, n), v in _REGISTRY.items() if n == name]


def list_types(lang: str | None = None) -> list[PIITypeDef]:
    """List all registered PII types, optionally filtered by language."""
    if lang:
        return [v for (l, _), v in _REGISTRY.items() if l == lang]
    return list(_REGISTRY.values())
