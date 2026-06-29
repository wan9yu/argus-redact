"""Verify that a custom faker_reserved callable routes through the Rust callback.

Task 9 of v0.7.4: wires custom_fakers={type: callable} into _core.replace() so
custom realistic-strategy fakers run in Rust's re-roll loop. The historical
pure-Python orchestrator has since been deleted (Rust owns the redact path), so
these tests assert the callback path's observable result directly.
"""

from __future__ import annotations

import warnings

import pytest

from argus_redact import redact
from argus_redact._core_loader import HAS_CORE
from argus_redact.pure.replacer import _faker_reserved_cached, replace
from argus_redact.specs.registry import PIITypeDef, register, unregister
from tests.conftest import make_match

# ---------------------------------------------------------------------------
# Fixed salt → deterministic fake; pin golden here once computed.
# salt=42 → bytes b'\x00\x00\x00\x00\x00\x00\x00*'
# seed = HMAC-SHA256(salt, "test_account:ACC-9876543210")
# rng drives: randint(0,9) × 10, joined as digits
# golden computed by running _ShakeRng with that seed.
# ---------------------------------------------------------------------------
_SALT = 42
_INPUT_VALUE = "ACC-9876543210"
_ENTITY_TYPE = "test_account"
_GOLDEN_FAKE = "TEST-9126154789"  # see: replacer._ShakeRng golden derivation


def _account_faker(value: str, rng) -> tuple[str, list[str]]:
    """Simple custom faker: replaces any account number with TEST-XXXXXXXXXX."""
    digits = "".join(str(rng.randint(0, 9)) for _ in range(10))
    fake = "TEST-" + digits
    return fake, []


@pytest.fixture(autouse=True)
def _register_test_account(monkeypatch):
    """Register a custom test_account PII type with faker_reserved, then clean up."""
    td = PIITypeDef(
        name=_ENTITY_TYPE,
        lang="shared",
        format="ACC-NNNNNNNNNN",
        strategy="realistic",
        faker_reserved=_account_faker,
    )
    register(td)
    _faker_reserved_cached.cache_clear()
    yield
    unregister("shared", _ENTITY_TYPE)
    _faker_reserved_cached.cache_clear()


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_routes_through_rust_callback():
    """Custom faker_reserved must run via the Rust callback (the only redact path).

    With the pure-Python orchestrator deleted, ``replace()`` always takes the
    Rust path; a custom faker fires via the ``PyFakerFactory`` callback. The
    deterministic golden below proves the callback actually ran.
    """

    text = f"Account number {_INPUT_VALUE}"
    entities = [make_match(_INPUT_VALUE, _ENTITY_TYPE, text.index(_INPUT_VALUE))]
    config = {_ENTITY_TYPE: {"strategy": "realistic"}}

    redacted, key, aliases = replace(text, entities, config=config, salt=_SALT, langs=["en"])

    # Entity was replaced (not left as original)
    assert _INPUT_VALUE not in redacted, f"Input value must be redacted but found in: {redacted!r}"

    # Key maps fake → original
    assert len(key) == 1, f"Expected 1 key entry, got {key}"
    fake = next(iter(key))
    assert key[fake] == _INPUT_VALUE, f"Key must map fake→original, got {key}"

    # Fake matches the custom faker's shape
    assert fake.startswith("TEST-"), f"Expected TEST- prefix, got {fake!r}"
    assert len(fake) == len("TEST-") + 10, f"Unexpected length for {fake!r}"

    # Golden: same salt → same fake (deterministic)
    assert fake == _GOLDEN_FAKE, f"Golden mismatch: expected {_GOLDEN_FAKE!r}, got {fake!r}"


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_key_maps_fake_to_original():
    """The key dict must contain fake→original after the Rust callback path."""

    text = f"ref {_INPUT_VALUE} end"
    entities = [make_match(_INPUT_VALUE, _ENTITY_TYPE, text.index(_INPUT_VALUE))]
    config = {_ENTITY_TYPE: {"strategy": "realistic"}}

    _, key, _ = replace(text, entities, config=config, salt=_SALT, langs=["en"])

    assert list(key.values()) == [_INPUT_VALUE], (
        f"Key values must be [{_INPUT_VALUE!r}], got {list(key.values())}"
    )


# ---------------------------------------------------------------------------
# Adapter-default parity: a custom type's registry-declared strategy must be
# honored WITHOUT explicit per-call config. Pre-port `_build_type_info` read
# the default strategy from the LIVE registry (`_resolve_default_strategy`), so
# a `realistic`+`faker_reserved` adapter fired its custom faker and a
# `pseudonym`-default adapter pseudonymized — both with NO config override. The
# c872064 SSOT port hardcoded a built-in-only strategy table in Rust, which
# downgraded every custom type's default to `remove`, silently killing the
# custom faker / pseudonym default. These tests lock the registry-default path.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_adapter_realistic_default_fires_custom_faker_without_config():
    """A `realistic`-default adapter must fire its faker with NO config override.

    Pre-port: `_resolve_default_strategy('vehicle_vin')` → 'realistic' (the
    typedef's declared strategy), so the custom faker ran. Post-port the Rust
    built-in table downgraded it to 'remove' → `VEHI-NNNNN` pseudonym, killing
    the faker. Expected output is byte-identical to pre-port.
    """

    def vin_faker(value, rng):
        return ("FAKE-VIN-0000", ["vin-alias"])

    td = PIITypeDef(
        name="vehicle_vin",
        lang="en",
        format="VIN",
        strategy="realistic",
        faker_reserved=vin_faker,
        sensitivity=2,
    )
    register(td)
    _faker_reserved_cached.cache_clear()
    try:
        pm = make_match("1HGCM82633A004352", "vehicle_vin", 7)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out = redact(
                "VIN is 1HGCM82633A004352 today",
                mode="fast",
                lang=["en"],
                salt=5,
                _pre_detected=[pm],
            )[0]
        # Pre-port (c872064^): registry strategy 'realistic' → custom faker.
        assert out == "VIN is FAKE-VIN-0000 today", (
            f"adapter custom faker must fire from registry default; got {out!r}"
        )
    finally:
        unregister("en", "vehicle_vin")
        _faker_reserved_cached.cache_clear()


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_adapter_pseudonym_default_applies_without_config():
    """A `pseudonym`-default adapter must pseudonymize with NO config override.

    Pre-port read the 'pseudonym' default from the registry; post-port the Rust
    built-in table downgraded an unknown type to 'remove'. For a non-realistic
    reversible strategy the observable output is the type-prefixed code, but the
    `default_strategy` recorded in the per-type info differs ('pseudonym' vs
    'remove'); assert via `_build_type_info` so the regression is visible even
    where 'remove' and 'pseudonym' happen to render the same code shape.
    """
    from argus_redact.pure.replacer import _build_type_info

    td = PIITypeDef(
        name="loyalty_id",
        lang="en",
        format="LID",
        strategy="pseudonym",
        sensitivity=2,
    )
    register(td)
    _faker_reserved_cached.cache_clear()
    try:
        pm = make_match("LID-42", "loyalty_id", 0)
        info, _ = _build_type_info([pm], None, ["en"])
        assert info["loyalty_id"]["strategy"] == "pseudonym", (
            "adapter default strategy must come from the live registry"
        )
        assert info["loyalty_id"]["default_strategy"] == "pseudonym", (
            f"default_strategy must be 'pseudonym' from registry, got "
            f"{info['loyalty_id']['default_strategy']!r}"
        )
    finally:
        unregister("en", "loyalty_id")
        _faker_reserved_cached.cache_clear()
