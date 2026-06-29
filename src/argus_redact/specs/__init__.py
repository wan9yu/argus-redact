"""PII type specifications — single source of truth for all PII types.

Each PIITypeDef fully describes a PII type: structure, validation, context,
replacement strategy, and evidence. All downstream components (patterns,
generators, fixtures, docs) should derive from these definitions.
"""

from __future__ import annotations

# Auto-register all language specs on import.
#
# Known modules are imported first in the canonical registration order so
# the insertion order of the registry dict (and thus risk_data.ron) is stable.
# pkgutil.iter_modules then discovers any NEW modules that were added to
# specs/*.py without updating this list — they auto-import after the known set,
# so a forgotten module never causes a silent type absence.
#
# Excluded by rule:
#   - private modules (_*)       — internal helpers, no register() calls
#   - generator scripts (gen_*)  — build-time tools, not runtime modules
#   - registry itself            — defines register(), must not self-import
import importlib as _importlib
import pkgutil as _pkgutil

from .registry import PIITypeDef, get, list_types, lookup

# Canonical load order (determines registry insertion order → risk_data.ron order).
_KNOWN_MOD_ORDER = ("zh", "en", "shared", "intl")
_EXCLUDED_PREFIXES = ("_", "gen_")
_EXCLUDED_NAMES = frozenset({"registry"})


def _discover_spec_modules() -> list[str]:
    """Return spec submodule names to auto-import, in canonical load order.

    Known modules first (stable registry insertion order → stable
    ``risk_data.ron``), then any newly-added modules discovered via
    ``pkgutil``, alphabetically. Excludes private (``_*``), generator
    (``gen_*``), and the registry module itself (imported directly above).

    Exposed (rather than inlined in the import loop) so the registration-
    completeness guard test shares this ONE discovery source — a module this
    function would skip is exactly a module that would silently never register.
    """
    extra = sorted(
        _m
        for _importer, _m, _ispkg in _pkgutil.iter_modules(__path__)
        if not any(_m.startswith(_p) for _p in _EXCLUDED_PREFIXES)
        and _m not in _EXCLUDED_NAMES
        and _m not in _KNOWN_MOD_ORDER
    )
    return [*_KNOWN_MOD_ORDER, *extra]


for _modname in _discover_spec_modules():
    try:
        _importlib.import_module(f"argus_redact.specs.{_modname}")
    except ImportError:
        pass

__all__ = ["PIITypeDef", "get", "list_types", "lookup"]
