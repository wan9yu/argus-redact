"""``StreamingRedactor.export_state()`` no longer leaks salt by default.

Pre-fix, the exported state dict included both the salt (cryptographic root
of trust) and ``accumulated_key`` (plaintext originals). Anyone reading the
serialized form recovered both: the originals directly, plus the ability
to deterministically regenerate fakes for new inputs under the same salt.
v0.6.2+ excludes salt by default; ``from_state`` requires explicit
``salt=`` kwarg.
"""

from __future__ import annotations

import warnings

import pytest


@pytest.fixture
def salt() -> bytes:
    return b"streaming-export-test-salt-32!"


def test_export_state_default_excludes_salt(salt):
    from argus_redact import StreamingRedactor

    r = StreamingRedactor(salt=salt)
    state = r.export_state()
    assert "salt" not in state, "v0.6.2: salt must NOT be in default export"


def test_export_state_with_include_salt_kwarg_warns(salt):
    """Back-compat path emits DeprecationWarning."""
    from argus_redact import StreamingRedactor

    r = StreamingRedactor(salt=salt)
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        state = r.export_state(include_salt=True)
    assert state.get("salt") == salt.hex()
    assert any(
        issubclass(w.category, DeprecationWarning) and "include_salt" in str(w.message)
        for w in captured
    )


def test_from_state_with_explicit_salt_kwarg_round_trips(salt):
    from argus_redact import StreamingRedactor

    r1 = StreamingRedactor(salt=salt)
    r1.feed("请拨打 13912345678 联系王建国")
    state = r1.export_state()  # no salt embedded
    assert "salt" not in state

    r2 = StreamingRedactor.from_state(state, salt=salt)
    assert r2.aggregate_key() == r1.aggregate_key()


def test_from_state_legacy_dump_with_embedded_salt_loads_with_warning(salt):
    """v0.6.0/v0.6.1 dumps that have salt embedded still load — but warn."""
    from argus_redact import StreamingRedactor

    r1 = StreamingRedactor(salt=salt)
    legacy_state = r1.export_state(include_salt=True)  # legacy shape
    # The export already emitted a DeprecationWarning; clear it to test from_state
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        r2 = StreamingRedactor.from_state(legacy_state)  # no salt= kwarg
    assert r2 is not None
    assert any(
        issubclass(w.category, DeprecationWarning) and "salt" in str(w.message)
        for w in captured
    ), "no DeprecationWarning emitted for legacy embedded salt"


def test_from_state_no_salt_anywhere_raises():
    """No kwarg AND no embedded salt → raise ValueError."""
    from argus_redact import StreamingRedactor

    state_without_salt = {
        "version": 1,
        "accumulated_key": {},
        "lang": "zh",
        "mode": "fast",
        "display_marker": None,
        "names": None,
        "types": None,
        "types_exclude": None,
        "strict_input": True,
        "reserved_names": None,
    }
    with pytest.raises(ValueError, match="salt"):
        StreamingRedactor.from_state(state_without_salt)


def test_from_state_explicit_salt_overrides_legacy_embedded(salt):
    """If both kwarg and embedded salt exist, kwarg wins (caller-explicit principle)."""
    from argus_redact import StreamingRedactor

    r1 = StreamingRedactor(salt=salt)
    legacy_state = r1.export_state(include_salt=True)
    other_salt = b"other-salt-32-bytes-padding-pad!"

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r2 = StreamingRedactor.from_state(legacy_state, salt=other_salt)

    # Effective salt should be other_salt (the kwarg), not legacy_state["salt"]
    assert r2._salt == other_salt
