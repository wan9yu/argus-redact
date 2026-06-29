"""Frozen goldens for the Rust ``_core.ShakeRng`` PRNG.

The Python ``_ShakeRng`` reference these once cross-checked against was the
parity oracle during the SHAKE-256 port. With the redact path now owned by
Rust, this file pins the Rust core's exact ``randint`` / ``choice`` stream for
fixed seeds — a regression here means the keyed PRNG drifted, which would break
every realistic-strategy fake's reproducibility.

Goldens captured from ``_core.ShakeRng`` (src build); regenerating them is a
deliberate, reviewable act (the KDF is bit-frozen across releases).
"""

import argus_redact._core as _core

# ── randint stream, seed = b"v0.7.4-shakerng-parity-seed-0001" ──────────────
_SEED_RANDINT = b"v0.7.4-shakerng-parity-seed-0001"
_GOLDEN_RANDINT_0_9 = [
    4,
    7,
    5,
    7,
    9,
    6,
    1,
    2,
    4,
    4,
    6,
    7,
    6,
    1,
    5,
    5,
    7,
    0,
    1,
    0,
    0,
    4,
    1,
    6,
    1,
    9,
    9,
    6,
    4,
    4,
    2,
    0,
    8,
    8,
    2,
    6,
    4,
    0,
    4,
    4,
]
# Same stream continues: randint(0, hi) for hi in (255, 1000, 7).
_GOLDEN_RANDINT_HI = [146, 718, 0]

# ── choice stream, seed = b"choice-parity-seed-padding-00001" ───────────────
_SEED_CHOICE = b"choice-parity-seed-padding-00001"
_CHOICE_POOL = ["a", "b", "c", "d", "e"]
_GOLDEN_CHOICE = [
    "d",
    "e",
    "b",
    "d",
    "b",
    "e",
    "d",
    "a",
    "a",
    "b",
    "e",
    "d",
    "a",
    "d",
    "e",
    "e",
    "b",
    "e",
    "d",
    "a",
]


def test_core_shakerng_randint_stream_is_frozen():
    rs = _core.ShakeRng(_SEED_RANDINT)
    got = [rs.randint(0, 9) for _ in range(len(_GOLDEN_RANDINT_0_9))]
    assert got == _GOLDEN_RANDINT_0_9
    got_hi = [rs.randint(0, hi) for hi in (255, 1000, 7)]
    assert got_hi == _GOLDEN_RANDINT_HI


def test_core_shakerng_choice_stream_is_frozen():
    rs = _core.ShakeRng(_SEED_CHOICE)
    got = [rs.choice(_CHOICE_POOL) for _ in range(len(_GOLDEN_CHOICE))]
    assert got == _GOLDEN_CHOICE
