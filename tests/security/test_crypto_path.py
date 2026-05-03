"""Cryptographic-root invariants for the realistic-strategy fake derivation.

These tests guard against the v0.6.0-era audit findings:
- H1: salt entropy was truncated to 8 bytes / 63 bits
- H4: Mersenne Twister (random.Random) drove adversarial fake selection
- M1: hash(entity_type) was process-randomized via PYTHONHASHSEED
- L7: HMAC-SHA256 truncation to 64 bits negated key strength
"""

from __future__ import annotations

import subprocess
import sys

import pytest


def test_full_salt_bytes_used_in_hmac():
    """Salt bytes after position 8 must change the derivation output.

    Pre-fix, only salt[:8] flowed into the HMAC (the rest was silently dropped).
    """
    from argus_redact.pure.replacer import _seed_from_value

    s1 = b"x" * 8 + b"A" * 24
    s2 = b"x" * 8 + b"B" * 24
    out1 = _seed_from_value("v", "phone", s1)
    out2 = _seed_from_value("v", "phone", s2)
    assert out1 != out2, "salt bytes after position 8 are ignored — entropy collapsed"


def test_seed_from_value_returns_bytes_not_int():
    """Pre-fix returned int (8-byte truncation); post-fix returns full SHA-256 digest."""
    from argus_redact.pure.replacer import _seed_from_value

    out = _seed_from_value("v", "phone", b"k" * 32)
    assert isinstance(out, bytes), f"expected bytes, got {type(out).__name__}"
    assert len(out) == 32, f"expected 32-byte HMAC-SHA256 digest, got {len(out)} bytes"


def test_entity_type_seed_offset_stable_across_processes(tmp_path):
    """hash(entity_type) is randomized via PYTHONHASHSEED — replaced with SHA-256."""
    import os

    repo_src = os.path.join(os.path.dirname(__file__), "..", "..", "src")
    code = (
        "from argus_redact.pure.replacer import _type_seed_offset; "
        "print(_type_seed_offset('phone'))"
    )
    base_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": os.path.abspath(repo_src),
    }
    out1 = subprocess.check_output(
        [sys.executable, "-c", code], env={**base_env, "PYTHONHASHSEED": "1"}
    )
    out2 = subprocess.check_output(
        [sys.executable, "-c", code], env={**base_env, "PYTHONHASHSEED": "2"}
    )
    assert out1 == out2, "entity_type seed depends on PYTHONHASHSEED — not deterministic"


def test_shake_rng_replaces_random_in_generate_unique_fake():
    """Faker output must derive from a SHAKE-256 stream, not Mersenne Twister."""
    import argus_redact.pure.replacer as r

    src = open(r.__file__, encoding="utf-8").read()
    fn_start = src.find("def _generate_unique_fake")
    assert fn_start != -1
    # Find end of function (next def at column 0)
    after = src[fn_start:]
    next_def = after.find("\ndef ", 1)
    fn_body = after[: next_def if next_def != -1 else len(after)]
    assert "random.Random" not in fn_body, (
        "v0.6.1+ must not use random.Random (Mersenne Twister) in the realistic faker path"
    )


def test_shake_rng_randint_uniform():
    """ShakeRng.randint(a, b) must produce uniform output (chi-square sanity check)."""
    from argus_redact.pure.replacer import _ShakeRng

    counts = {i: 0 for i in range(10)}
    # Use distinct seeds so we sample many independent streams
    for s in range(2000):
        rng = _ShakeRng(seed=s.to_bytes(32, "big"))
        counts[rng.randint(0, 9)] += 1
    # 2000 samples / 10 buckets = 200 expected; allow generous slack
    for k, v in counts.items():
        assert 130 < v < 270, f"bucket {k} count {v} far from uniform"


def test_shake_rng_choice_deterministic_for_same_seed():
    """Same seed → same choice (determinism is required for reproducibility)."""
    from argus_redact.pure.replacer import _ShakeRng

    seq = ("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
    seed = b"deterministic-seed-32-bytes-pad!"
    r1 = _ShakeRng(seed=seed)
    r2 = _ShakeRng(seed=seed)
    assert r1.choice(seq) == r2.choice(seq)
    assert r1.choice(seq) == r2.choice(seq)


def test_shake_rng_compat_with_random_random_api():
    """The RNG must expose the subset of random.Random's API used by faker code."""
    from argus_redact.pure.replacer import _ShakeRng

    rng = _ShakeRng(seed=b"\x00" * 32)
    # randint
    n = rng.randint(1, 99)
    assert 1 <= n <= 99
    # choice
    c = rng.choice(["x", "y", "z"])
    assert c in ("x", "y", "z")


def test_pseudonym_llm_uses_full_salt_bytes_end_to_end():
    """End-to-end: salt bytes after position 8 must change downstream_text.

    Pre-fix, ``_seed_from_salt`` truncated user salt to 8 bytes + 63 bits;
    those bytes were the SOLE input to the realistic faker derivation. Two
    32-byte salts that share the first 8 bytes produced identical output —
    63-bit effective entropy regardless of caller intent.
    """
    from argus_redact import redact_pseudonym_llm

    # Both salts share first 8 bytes; differ only in bytes 8..32.
    s1 = b"x" * 8 + b"A" * 24
    s2 = b"x" * 8 + b"B" * 24
    text = "patient John Smith phone (415) 555-1212"
    r1 = redact_pseudonym_llm(text, salt=s1, lang="en")
    r2 = redact_pseudonym_llm(text, salt=s2, lang="en")
    assert r1.downstream_text != r2.downstream_text, (
        "salt bytes after position 8 ignored — entropy collapsed at the salt-to-seed step"
    )


def test_salt_to_bytes_preserves_full_input():
    """``_salt_to_bytes`` must pass user salt through verbatim (no 8-byte truncation)."""
    from argus_redact.glue.redact_pseudonym_llm import _salt_to_bytes

    salt = b"\x01" * 64
    assert _salt_to_bytes(salt) == salt
    assert _salt_to_bytes(None) is None
