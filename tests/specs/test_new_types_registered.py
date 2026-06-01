"""v0.6.8 registers phone_landline / date / url as first-class PII types.

After C2 lands (DEFAULT_STRATEGIES dict deleted), the dict-existence checks
flip to typedef-existence checks. v0.6.8 commits pass both at every commit
boundary because C0 wires both paths and C2 only deletes the dict.
"""
from __future__ import annotations

import pytest

from argus_redact.specs.registry import lookup


@pytest.mark.parametrize("type_name,expected_strategy,expected_prefix", [
    ("phone_landline", "mask", "LL"),
    ("date", "remove", "DATE"),
    ("url", "remove", "URL"),
])
def test_type_has_dict_entries(type_name, expected_strategy, expected_prefix):
    """Until C2 deletes DEFAULT_STRATEGIES, these dict entries exist."""
    from argus_redact.pure.replacer import DEFAULT_PREFIXES, DEFAULT_STRATEGIES
    assert DEFAULT_STRATEGIES.get(type_name) == expected_strategy, (
        f"{type_name}: DEFAULT_STRATEGIES says {DEFAULT_STRATEGIES.get(type_name)!r}, "
        f"expected {expected_strategy!r}"
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
    """After C2 (PIITypeDef.strategy as runtime SSOT), the typedef
    is the only place strategy lives. v0.6.8 C0 prepares by adding entries
    in BOTH places; C2 removes the dict.
    """
    typedef_list = lookup(type_name)
    assert typedef_list, f"{type_name} has no typedef in registry"
    assert typedef_list[0].strategy == expected_strategy, (
        f"{type_name}: typedef.strategy={typedef_list[0].strategy!r}, "
        f"expected {expected_strategy!r}"
    )
