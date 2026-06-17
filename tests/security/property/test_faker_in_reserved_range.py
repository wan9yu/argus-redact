"""Realistic-strategy fakers must emit values inside their reserved range.

A faker drift would silently emit real third-party PII as the "fake"; this
property is the runtime backstop that drift tests catch at static-time too.
"""

from __future__ import annotations

import re

from hypothesis import given
from hypothesis import strategies as st

import argus_redact._core as _core

_RESERVED_RANGE_PATTERNS = dict(_core.reserved_range_patterns())
from argus_redact.pure.replacer import _resolve_realistic_faker
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
    """Source every built-in faker from the Rust SSOT, not from a now-absent
    Python ``faker_reserved`` callable.

    v0.7.5 made built-ins callable-less (every typedef carries
    ``faker_reserved=None``), so filtering on ``td.faker_reserved`` would yield
    ZERO cases and silently vacuum this property test. Instead we resolve each
    registered (type, lang) through ``_resolve_realistic_faker`` — the same
    resolver the redact path uses — and take the ``("builtin", name)`` hits.

    A handful of built-ins are noise fakers (``fake_age_noise``,
    ``fake_date_of_birth_noise``) with no reserved-range pattern to assert
    against; they fall out via the ``if not valid_keys`` skip, exactly as the
    pre-v0.7.5 version skipped them.
    """
    seen_langs: dict[str, set[str]] = {}
    for td in list_types():
        seen_langs.setdefault(td.name, set()).add(td.lang)

    cases = []
    deduped: set[str] = set()
    for name, langs in sorted(seen_langs.items()):
        for lang in sorted(langs):
            resolved = _resolve_realistic_faker(name, [lang])
            if resolved is None or resolved[0] != "builtin":
                continue
            faker_name = resolved[1]
            keys = _MULTI_PATTERN_OVERRIDES.get(name, (f"{name}_{lang}",))
            # Only include if at least one pattern key exists in scanner registry
            valid_keys = tuple(k for k in keys if k in _RESERVED_RANGE_PATTERNS)
            if not valid_keys:
                continue
            # Dedupe so a faker shared across langs (resolved identically) is
            # exercised once per (faker, pattern) shape.
            dedupe_key = (faker_name, valid_keys)
            if dedupe_key in deduped:
                continue
            deduped.add(dedupe_key)
            cases.append((faker_name, valid_keys, name))
    return cases


_FAKERS_TO_TEST = _build_faker_cases()

# Guard against silent re-vacuuming: if the SSOT ever stops yielding built-in
# fakers (e.g. a future refactor changes the resolver contract), fail loudly at
# collection time instead of passing zero cases.
assert _FAKERS_TO_TEST, "no built-in fakers to test"


def test_reserved_range_case_list_is_not_vacuous():
    """The property test below iterates ``_FAKERS_TO_TEST``; if that list is
    empty the property runs zero assertions and passes vacuously. Lock the
    count so a regression to the v0.7.5 callable-less typedefs (which silently
    emptied the list) is caught directly."""
    assert len(_FAKERS_TO_TEST) >= 20, len(_FAKERS_TO_TEST)


@PROPERTY_SETTINGS
@given(
    salt=st.binary(min_size=32, max_size=32),
    value=st.text(min_size=1, max_size=50),
)
def test_each_faker_emits_reserved_range(salt, value):
    """Every faker, called via the wrapper, emits a string matching its
    reserved-range scanner pattern."""
    for faker_name, pattern_keys, type_name in _FAKERS_TO_TEST:
        fake, _aliases = _core.generate_unique_fake(
            faker_name,
            value=value,
            type_=type_name,
            salt=salt,
            used=set(),
        )
        matched = any(
            re.search(_RESERVED_RANGE_PATTERNS[key], fake) for key in pattern_keys
        )
        assert matched, (
            f"{faker_name} emitted {fake!r} which does not match any of "
            f"reserved-range patterns {pattern_keys}"
        )
