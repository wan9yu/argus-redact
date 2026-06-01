"""v0.6.8 registers phone_landline / date / url as first-class PII types.

C2 deleted DEFAULT_STRATEGIES. Strategy is now read exclusively from
PIITypeDef.strategy via _resolve_default_strategy(). DEFAULT_PREFIXES stays.
"""
from __future__ import annotations

import pytest

from argus_redact.specs.registry import lookup


@pytest.mark.parametrize("type_name,expected_strategy,expected_prefix", [
    ("phone_landline", "mask", "LL"),
    ("date", "remove", "DATE"),
    ("url", "remove", "URL"),
])
def test_type_has_typedef_and_prefix_entries(type_name, expected_strategy, expected_prefix):
    """C2: typedef is the runtime SSOT; DEFAULT_PREFIXES still exists."""
    from argus_redact.pure.replacer import DEFAULT_PREFIXES, _resolve_default_strategy
    assert _resolve_default_strategy(type_name) == expected_strategy, (
        f"{type_name}: _resolve_default_strategy says "
        f"{_resolve_default_strategy(type_name)!r}, expected {expected_strategy!r}"
    )
    assert DEFAULT_PREFIXES.get(type_name) == expected_prefix, (
        f"{type_name}: DEFAULT_PREFIXES says {DEFAULT_PREFIXES.get(type_name)!r}, "
        f"expected {expected_prefix!r}"
    )


@pytest.mark.parametrize("type_name,expected_strategy", [
    ("phone_landline", "mask"),
    ("date", "remove"),
    ("url", "remove"),
])
def test_type_has_typedef_entry(type_name, expected_strategy):
    """PIITypeDef.strategy is the single source of truth after C2."""
    typedef_list = lookup(type_name)
    assert typedef_list, f"{type_name} has no typedef in registry"
    assert typedef_list[0].strategy == expected_strategy, (
        f"{type_name}: typedef.strategy={typedef_list[0].strategy!r}, "
        f"expected {expected_strategy!r}"
    )
