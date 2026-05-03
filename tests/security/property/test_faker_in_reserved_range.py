"""Realistic-strategy fakers must emit values inside their reserved range.

A faker drift would silently emit real third-party PII as the "fake"; this
property is the runtime backstop that drift tests catch at static-time too.
"""

from __future__ import annotations

import re

from hypothesis import given
from hypothesis import strategies as st

from argus_redact.pure.replacer import _generate_unique_fake
from argus_redact.pure.reserved_range_scanner import _RESERVED_RANGE_PATTERNS
from argus_redact.specs.registry import list_types
from tests.security.property.conftest import PROPERTY_SETTINGS


# Some types map to multiple scanner patterns or have a non-default key
# shape (e.g. ``ip_address`` can emit ipv4 OR ipv6; ``mac_address`` is keyed
# by ``mac_shared`` rather than ``mac_address_shared``).
_MULTI_PATTERN_OVERRIDES: dict[str, tuple[str, ...]] = {
    "ip_address": ("ipv4_shared", "ipv6_shared"),
    "mac_address": ("mac_shared",),
}


def _build_faker_cases() -> list[tuple]:
    cases = []
    for td in list_types():
        if td.faker_reserved is None:
            continue
        keys = _MULTI_PATTERN_OVERRIDES.get(td.name, (f"{td.name}_{td.lang}",))
        # Only include if at least one pattern key exists in scanner registry
        valid_keys = tuple(k for k in keys if k in _RESERVED_RANGE_PATTERNS)
        if not valid_keys:
            continue
        cases.append((td.faker_reserved, valid_keys, td.name))
    return cases


_FAKERS_TO_TEST = _build_faker_cases()


@PROPERTY_SETTINGS
@given(
    seed=st.binary(min_size=32, max_size=32),
    value=st.text(min_size=1, max_size=50),
)
def test_each_faker_emits_reserved_range(seed, value):
    """Every faker, called via the wrapper, emits a string matching its
    reserved-range scanner pattern."""
    for faker_fn, pattern_keys, type_name in _FAKERS_TO_TEST:
        fake, _aliases = _generate_unique_fake(
            faker_fn,
            value=value,
            type_name=type_name,
            salt=seed,
            used=set(),
        )
        matched = any(
            re.search(_RESERVED_RANGE_PATTERNS[key], fake) for key in pattern_keys
        )
        assert matched, (
            f"{faker_fn.__name__} emitted {fake!r} which does not match any of "
            f"reserved-range patterns {pattern_keys}"
        )
