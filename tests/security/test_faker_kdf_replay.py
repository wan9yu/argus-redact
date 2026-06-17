"""Faker KDF replay vectors — bit-identity freeze for ``_ShakeRng``.

The realistic-strategy fakers are driven by ``_ShakeRng``: a SHAKE-256 stream
keyed by an ``HMAC-SHA256`` master derived from ``(salt, type, value)``. Every
realistic fake value is a deterministic function of this stream, so any
accidental change to the seed derivation, the XOF byte layout, or the
``randint`` byte-consumption silently changes every fake across releases —
breaking caches and any "same salt → same fake" guarantee.

These vectors are frozen from the current Python implementation. They are the
ground truth that the Rust ``ShakeRng`` port (``shake_rng.rs``) must reproduce
byte-for-byte; the same constants are mirrored as Rust unit tests. If a value
here ever changes, the change is a cryptographic-chain break requiring a
major-version bump and a migration note — NOT a vector to silently update.

Mirror of ``test_pseudonym_chain_replay.py`` (the pseudonym KDF), for the
realistic-faker KDF.
"""

import argus_redact._core as _core

_seed_from_value = _core.seed_from_value
_ShakeRng = _core.ShakeRng

# ── Seed 1: _seed_from_value("Alice", "person", b"\x00" * 8) ────────────────
SEED1_HEX = "a2e1895de10e12dc452f7e3bde7d98219e1e0ed794726117688a80cbd8b5aff6"
SEED1_RANDINT_0_9 = [5, 2, 3, 2, 3, 2, 8, 7, 8, 3, 3, 3, 8, 0, 6, 7, 5, 7, 0, 8]
# 5×randint(1960,2005) + 5×randint(0,999) + 5×randint(1,28) on a fresh stream
SEED1_RANDINT_MIXED = [1966, 1975, 1978, 1961, 1976, 765, 111, 591, 628, 803, 24, 4, 15, 17, 21]

# ── Seed 2: _seed_from_value("测试", "phone", (42).to_bytes(8, "big")) ───────
SEED2_HEX = "cf18e5b4d4c6218f4edbb1529ab55e98efff4e32f95cd2f4c1a758017bcca4f7"
SEED2_RANDINT_0_9 = [1, 5, 1, 2, 6, 8, 0, 2, 0, 6, 3, 9, 2, 7, 6, 9, 8, 3, 6, 2]
SEED2_RANDINT_MIXED = [2001, 1989, 1985, 2000, 1978, 122, 426, 177, 709, 695, 25, 6, 23, 5, 24]


def test_seed_from_value_hmac_seed1():
    """HMAC-SHA256(salt, "type:value") must stay byte-stable."""
    seed = _seed_from_value("Alice", "person", b"\x00" * 8)
    assert seed.hex() == SEED1_HEX


def test_seed_from_value_hmac_seed2():
    seed = _seed_from_value("测试", "phone", (42).to_bytes(8, "big"))
    assert seed.hex() == SEED2_HEX


def test_shake_rng_randint_0_9_seed1():
    seed = _seed_from_value("Alice", "person", b"\x00" * 8)
    r = _ShakeRng(seed)
    assert [r.randint(0, 9) for _ in range(20)] == SEED1_RANDINT_0_9


def test_shake_rng_randint_mixed_seed1():
    seed = _seed_from_value("Alice", "person", b"\x00" * 8)
    r = _ShakeRng(seed)
    seq = (
        [r.randint(1960, 2005) for _ in range(5)]
        + [r.randint(0, 999) for _ in range(5)]
        + [r.randint(1, 28) for _ in range(5)]
    )
    assert seq == SEED1_RANDINT_MIXED


def test_shake_rng_randint_0_9_seed2():
    seed = _seed_from_value("测试", "phone", (42).to_bytes(8, "big"))
    r = _ShakeRng(seed)
    assert [r.randint(0, 9) for _ in range(20)] == SEED2_RANDINT_0_9


def test_shake_rng_randint_mixed_seed2():
    seed = _seed_from_value("测试", "phone", (42).to_bytes(8, "big"))
    r = _ShakeRng(seed)
    seq = (
        [r.randint(1960, 2005) for _ in range(5)]
        + [r.randint(0, 999) for _ in range(5)]
        + [r.randint(1, 28) for _ in range(5)]
    )
    assert seq == SEED2_RANDINT_MIXED


def test_choice_is_randint_indexed():
    """choice(seq) == seq[randint(0, len-1)] — the stream is shared."""
    seed = _seed_from_value("Alice", "person", b"\x00" * 8)
    seq = list("abcdefghij")  # len 10
    a = _ShakeRng(seed)
    b = _ShakeRng(seed)
    for _ in range(10):
        assert a.choice(seq) == seq[b.randint(0, len(seq) - 1)]
