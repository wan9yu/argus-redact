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

import argus_redact._core as _core
from argus_redact.pure.replacer import _faker_reserved_cached, replace
from argus_redact.specs import en as _en  # noqa: F401  registry side-effect import
from argus_redact.specs.fakers_en_reserved import RESERVED_PERSON_NAMES_EN
from argus_redact.specs.fakers_zh_reserved import RESERVED_PERSON_NAMES
from argus_redact.specs.registry import PIITypeDef, register, unregister
from tests.conftest import make_match


_SALT = b"identity-pass-test-salt-32-byte!"
_SALT_BYTES = _core.resolve_salt(_SALT)


def test_generate_unique_fake_rejects_value_equal_fake():
    """Re-roll guarantee through the public custom-faker path: even if the faker
    returns the input, the Rust re-roll loop rejects the identity-pass and rolls
    again until it gets a non-identity fake."""
    call_count = {"n": 0}

    def stubborn_faker(value, rng):
        call_count["n"] += 1
        # First two calls return identity; the third returns something else.
        if call_count["n"] <= 2:
            return value, []
        return f"FAKE-{call_count['n']}", []

    register(
        PIITypeDef(
            name="stubborn_faker_type",
            lang="shared",
            format="test",
            faker_reserved=stubborn_faker,
        )
    )
    try:
        _, key, _ = replace(
            "John Doe",
            [make_match("John Doe", "stubborn_faker_type", 0)],
            config={"stubborn_faker_type": {"strategy": "realistic"}},
            salt=_SALT,
        )
        fake = next(iter(key))
        assert fake != "John Doe"
        assert fake.startswith("FAKE-")
        assert call_count["n"] >= 3, "should have re-rolled past identity outputs"
    finally:
        unregister("shared", "stubborn_faker_type")
        _faker_reserved_cached.cache_clear()


def test_generate_unique_fake_raises_when_only_identity_available():
    """If the faker can only ever return the input, the Rust re-roll loop
    exhausts its attempts and surfaces the exhaustion error (ValueError on the
    Rust-callback path)."""

    def identity_faker(value, rng):
        return value, []

    register(
        PIITypeDef(
            name="identity_faker_type",
            lang="shared",
            format="test",
            faker_reserved=identity_faker,
        )
    )
    try:
        with pytest.raises(ValueError, match="unique fake"):
            replace(
                "John Doe",
                [make_match("John Doe", "identity_faker_type", 0)],
                config={"identity_faker_type": {"strategy": "realistic"}},
                salt=_SALT,
            )
    finally:
        unregister("shared", "identity_faker_type")
        _faker_reserved_cached.cache_clear()


@pytest.mark.parametrize("name", RESERVED_PERSON_NAMES_EN)
def test_en_reserved_pool_member_never_self_maps_through_wrapper(name):
    """For every name in the EN pool, the wrapper produces a different fake
    even when the input itself is a pool member."""
    fake, _ = _core.generate_unique_fake(
        "fake_person_en_reserved",
        value=name,
        type_=("person"),
        salt=_SALT_BYTES,
        used=set(),
    )
    assert fake != name, f"identity-pass: {name!r} mapped to itself"
    assert fake in RESERVED_PERSON_NAMES_EN, f"fake {fake!r} not in reserved pool"


@pytest.mark.parametrize("name", RESERVED_PERSON_NAMES)
def test_zh_reserved_pool_member_never_self_maps_through_wrapper(name):
    """Same identity-pass guard for the zh cultural-placeholder pool."""
    fake, _ = _core.generate_unique_fake(
        "fake_person_reserved",
        value=name,
        type_=("person"),
        salt=_SALT_BYTES,
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
