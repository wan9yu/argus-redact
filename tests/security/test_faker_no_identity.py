"""Faker must never return the input value as the fake (identity-pass leak).

Pre-fix, ``_generate_unique_fake`` only checked ``fake not in used``. For
small reserved-name pools (10 entries each for zh/en), the HMAC-seeded RNG
could pick the input itself with ~10% probability — the redacted output
would be bit-identical to the input, key dict would store ``{name: name}``,
and round-trip tests would still pass. The leak was invisible to any
``assert input != redacted`` smoke test.
"""

from __future__ import annotations

import pytest

from argus_redact.pure import replacer as r
from argus_redact.specs import en as _en  # noqa: F401  registry side-effect import
from argus_redact.specs.fakers_en_reserved import (
    RESERVED_PERSON_NAMES_EN,
    fake_person_en_reserved,
)
from argus_redact.specs.fakers_zh_reserved import (
    RESERVED_PERSON_NAMES,
    fake_person_reserved as fake_person_zh_reserved,
)


_SALT = b"identity-pass-test-salt-32-byte!"


def test_generate_unique_fake_rejects_value_equal_fake():
    """Wrapper guarantee: even if the faker returns the input, the wrapper rerolls."""
    call_count = {"n": 0}

    def stubborn_faker(value, rng):
        call_count["n"] += 1
        # First two calls return identity; the third returns something else.
        if call_count["n"] <= 2:
            return value, []
        return f"FAKE-{call_count['n']}", []

    fake, _ = r._generate_unique_fake(
        stubborn_faker,
        value="John Doe",
        type_name="person",
        salt=_SALT,
        used=set(),
    )
    assert fake != "John Doe"
    assert fake.startswith("FAKE-")
    assert call_count["n"] >= 3, "wrapper should have re-rolled past identity outputs"


def test_generate_unique_fake_raises_when_only_identity_available():
    """If the faker cannot produce anything other than the input, the wrapper raises."""

    def identity_faker(value, rng):
        return value, []

    with pytest.raises(RuntimeError, match="unique fake"):
        r._generate_unique_fake(
            identity_faker,
            value="John Doe",
            type_name="person",
            salt=_SALT,
            used=set(),
        )


@pytest.mark.parametrize("name", RESERVED_PERSON_NAMES_EN)
def test_en_reserved_pool_member_never_self_maps_through_wrapper(name):
    """For every name in the EN pool, the wrapper produces a different fake
    even when the input itself is a pool member."""
    fake, _ = r._generate_unique_fake(
        fake_person_en_reserved,
        value=name,
        type_name="person",
        salt=_SALT,
        used=set(),
    )
    assert fake != name, f"identity-pass: {name!r} mapped to itself"
    assert fake in RESERVED_PERSON_NAMES_EN, f"fake {fake!r} not in reserved pool"


@pytest.mark.parametrize("name", RESERVED_PERSON_NAMES)
def test_zh_reserved_pool_member_never_self_maps_through_wrapper(name):
    """Same identity-pass guard for the zh cultural-placeholder pool."""
    fake, _ = r._generate_unique_fake(
        fake_person_zh_reserved,
        value=name,
        type_name="person",
        salt=_SALT,
        used=set(),
    )
    assert fake != name, f"identity-pass: {name!r} mapped to itself"
    assert fake in RESERVED_PERSON_NAMES, f"fake {fake!r} not in reserved pool"


def test_james_smith_removed_from_en_reserved():
    """v0.6.1: ``James Smith`` (statistically the most common US first+last)
    and ``Bob Loblaw`` (real name + sitcom reference) removed."""
    assert "James Smith" not in RESERVED_PERSON_NAMES_EN
    assert "Bob Loblaw" not in RESERVED_PERSON_NAMES_EN


def test_en_reserved_pool_has_at_least_ten_names():
    """Pool size guard: must remain ≥ 10 to satisfy the reroll budget."""
    assert len(RESERVED_PERSON_NAMES_EN) >= 10, (
        f"pool shrunk to {len(RESERVED_PERSON_NAMES_EN)} — under reroll budget"
    )
