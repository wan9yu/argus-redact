"""Verify that a custom faker_reserved callable routes through the Rust callback.

Task 9 of v0.7.4: wires custom_fakers={type: callable} into _core.replace() so
custom realistic-strategy fakers run in Rust's re-roll loop rather than falling
back to _replace_python.
"""

from __future__ import annotations

import pytest

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
def test_custom_faker_routes_through_rust_callback(monkeypatch):
    """Custom faker_reserved must invoke the Rust callback, NOT _replace_python.

    Proof: monkeypatch _replace_python to raise — if the call succeeds, it went
    through Rust+callback.
    """

    def _boom(*a, **k):
        raise AssertionError("_replace_python must NOT be called for custom faker")

    monkeypatch.setattr("argus_redact.pure.replacer._replace_python", _boom)

    text = f"Account number {_INPUT_VALUE}"
    entities = [make_match(_INPUT_VALUE, _ENTITY_TYPE, text.index(_INPUT_VALUE))]
    config = {_ENTITY_TYPE: {"strategy": "realistic"}}

    redacted, key, aliases = replace(
        text, entities, config=config, salt=_SALT, langs=["en"]
    )

    # Entity was replaced (not left as original)
    assert _INPUT_VALUE not in redacted, (
        f"Input value must be redacted but found in: {redacted!r}"
    )

    # Key maps fake → original
    assert len(key) == 1, f"Expected 1 key entry, got {key}"
    fake = next(iter(key))
    assert key[fake] == _INPUT_VALUE, f"Key must map fake→original, got {key}"

    # Fake matches the custom faker's shape
    assert fake.startswith("TEST-"), f"Expected TEST- prefix, got {fake!r}"
    assert len(fake) == len("TEST-") + 10, f"Unexpected length for {fake!r}"

    # Golden: same salt → same fake (deterministic)
    assert fake == _GOLDEN_FAKE, (
        f"Golden mismatch: expected {_GOLDEN_FAKE!r}, got {fake!r}"
    )


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_custom_faker_key_maps_fake_to_original(monkeypatch):
    """The key dict must contain fake→original after the Rust callback path."""

    def _boom(*a, **k):
        raise AssertionError("_replace_python must NOT be called")

    monkeypatch.setattr("argus_redact.pure.replacer._replace_python", _boom)

    text = f"ref {_INPUT_VALUE} end"
    entities = [make_match(_INPUT_VALUE, _ENTITY_TYPE, text.index(_INPUT_VALUE))]
    config = {_ENTITY_TYPE: {"strategy": "realistic"}}

    _, key, _ = replace(text, entities, config=config, salt=_SALT, langs=["en"])

    assert list(key.values()) == [_INPUT_VALUE], (
        f"Key values must be [{_INPUT_VALUE!r}], got {list(key.values())}"
    )
