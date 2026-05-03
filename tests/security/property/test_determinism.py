"""Same (salt, type, value) → same fake; different salts → different fakes (≥99%).

Determinism is the foundation of both reproducibility and PRvL R (restore
correctness). Divergence ensures salt entropy reaches the output and isn't
collapsed via earlier truncation bugs (audit H1).
"""

from __future__ import annotations

from hypothesis import HealthCheck, assume, given, settings, strategies as st

from argus_redact.pure.replacer import _ShakeRng, _seed_from_value


_HSettings = settings(
    database=None,
    deadline=None,
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow],
)


@_HSettings
@given(
    salt=st.binary(min_size=32, max_size=32),
    type_name=st.sampled_from(["phone", "person", "id_number", "ssn", "email"]),
    value=st.text(min_size=1, max_size=50),
)
def test_seed_from_value_deterministic(salt, type_name, value):
    """Two calls with same args must produce identical bytes."""
    out1 = _seed_from_value(value, type_name, salt)
    out2 = _seed_from_value(value, type_name, salt)
    assert out1 == out2
    assert isinstance(out1, bytes)
    assert len(out1) == 32


@_HSettings
@given(
    salt_a=st.binary(min_size=32, max_size=32),
    salt_b=st.binary(min_size=32, max_size=32),
    type_name=st.sampled_from(["phone", "person", "id_number"]),
    value=st.text(min_size=1, max_size=50),
)
def test_different_salts_diverge(salt_a, salt_b, type_name, value):
    """Different salts produce different outputs (probabilistically 1 - 2^-256)."""
    assume(salt_a != salt_b)
    out_a = _seed_from_value(value, type_name, salt_a)
    out_b = _seed_from_value(value, type_name, salt_b)
    assert out_a != out_b


@_HSettings
@given(
    seed=st.binary(min_size=32, max_size=32),
    n=st.integers(min_value=2, max_value=20),
)
def test_shake_rng_deterministic(seed, n):
    """_ShakeRng with the same seed produces the same randint sequence."""
    rng_a = _ShakeRng(seed)
    rng_b = _ShakeRng(seed)
    seq_a = [rng_a.randint(0, 999) for _ in range(n)]
    seq_b = [rng_b.randint(0, 999) for _ in range(n)]
    assert seq_a == seq_b
