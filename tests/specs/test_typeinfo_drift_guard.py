"""Drift guard: the Rust built-in TypeInfo fallback table vs the live registry.

`crates/argus-redact-core/src/typeinfo.rs` carries hardcoded built-in tables for
the per-type default *strategy*, *prefix*, and *category label*. Those tables are
the fallback used when no Python registry value is threaded in — i.e. the wasm
path, which has built-in types only and no Python registry.

On the PyO3 path the Python shim threads the live-registry value into
`_core.build_type_info` (so a runtime adapter type honors its declared strategy),
but the Rust *fallback* table must still stay in lockstep with the registry for
every built-in type, or the wasm build silently diverges from the Python build.

This sweeps EVERY registered type (`list_types()`) and asserts the Rust fallback
(`_core.build_type_info` called with NO registry-defaults map) reproduces:
  - `_resolve_default_strategy(name)`  (== `lookup(name)[0].strategy`)
  - `DEFAULT_PREFIXES.get(name, name.upper()[:4])`
  - `DEFAULT_CATEGORY_LABEL.get(name, f"[{name}]")`

A future registry change that diverges from the Rust fallback table fails here.
"""

from __future__ import annotations

import pytest

import argus_redact._core as _core
from argus_redact._core_loader import HAS_CORE
from argus_redact.pure.replacer import (
    DEFAULT_CATEGORY_LABEL,
    DEFAULT_PREFIXES,
    _resolve_default_strategy,
)
from argus_redact.specs.registry import list_types

# All distinct registered type names (49 across zh/en/shared at time of writing).
_ALL_TYPE_NAMES = sorted({td.name for td in list_types()})


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_at_least_all_builtin_types_swept():
    """Sanity: the sweep covers the full registry, not a hardcoded handful."""
    # Locks the guard against silently shrinking to a trivial set.
    assert len(_ALL_TYPE_NAMES) >= 40, (
        f"expected the full registry sweep (>=40 types), got {len(_ALL_TYPE_NAMES)}"
    )


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
@pytest.mark.parametrize("type_name", _ALL_TYPE_NAMES)
def test_rust_fallback_table_matches_registry(type_name):
    """For every built-in type, the Rust fallback table == registry-derived values.

    Calls `_core.build_type_info` with NO registry-defaults map so the Rust
    BUILT-IN fallback tables drive strategy/prefix/category-label — the exact
    code path the wasm build takes.
    """
    pm = _core.PatternMatch(type_name, type_name, 0, len(type_name), 1.0, 0)
    # No config, no registry-defaults map → Rust uses its built-in fallback.
    info = _core.build_type_info([pm], None, ["en"])
    ti = info[type_name]

    expected_strategy = _resolve_default_strategy(type_name)
    expected_prefix = DEFAULT_PREFIXES.get(type_name, type_name.upper()[:4])
    expected_label = DEFAULT_CATEGORY_LABEL.get(type_name, f"[{type_name}]")

    assert ti["default_strategy"] == expected_strategy, (
        f"{type_name}: Rust fallback default_strategy={ti['default_strategy']!r} "
        f"diverged from registry {expected_strategy!r}"
    )
    # With no config, effective strategy == default strategy.
    assert ti["strategy"] == expected_strategy, (
        f"{type_name}: Rust fallback strategy={ti['strategy']!r} != {expected_strategy!r}"
    )
    assert ti["prefix"] == expected_prefix, (
        f"{type_name}: Rust fallback prefix={ti['prefix']!r} != {expected_prefix!r}"
    )
    assert ti["default_category_label"] == expected_label, (
        f"{type_name}: Rust fallback category label={ti['default_category_label']!r} "
        f"!= {expected_label!r}"
    )
