"""Realistic-strategy fakers must emit values inside their reserved range.

A faker drift would silently emit real third-party PII as the "fake"; this
property is the runtime backstop that drift tests catch at static-time too.
"""

from __future__ import annotations

import re

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus_redact.pure.replacer import _generate_unique_fake
from argus_redact.pure.reserved_range_scanner import _RESERVED_RANGE_PATTERNS
from argus_redact.specs.fakers_en_reserved import (
    fake_phone_en_reserved,
    fake_ssn_en_reserved,
)
from argus_redact.specs.fakers_shared_reserved import (
    fake_email_reserved,
    fake_ip_reserved,
    fake_mac_reserved,
)
from argus_redact.specs.fakers_zh_reserved import (
    fake_address_reserved,
    fake_id_number_reserved,
    fake_phone_landline_reserved,
    fake_phone_reserved,
)

_HSettings = settings(
    database=None,
    deadline=None,
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
)


# (faker, scanner_pattern_keys, type_name) tuples. A faker may legitimately
# emit values matching any one of several reserved patterns (e.g. fake_ip
# returns IPv4 or IPv6 depending on input shape).
_FAKERS_TO_TEST = [
    (fake_phone_reserved, ("phone_zh",), "phone"),
    (fake_phone_landline_reserved, ("phone_landline_zh",), "phone_landline"),
    (fake_id_number_reserved, ("id_number_zh",), "id_number"),
    (fake_address_reserved, ("address_zh",), "address"),
    (fake_phone_en_reserved, ("phone_en",), "phone"),
    (fake_ssn_en_reserved, ("ssn_en",), "ssn"),
    (fake_email_reserved, ("email_shared",), "email"),
    (fake_ip_reserved, ("ipv4_shared", "ipv6_shared"), "ip_address"),
    (fake_mac_reserved, ("mac_shared",), "mac_address"),
]


@_HSettings
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
