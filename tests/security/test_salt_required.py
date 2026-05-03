"""Realistic strategy + pseudonym-llm now require an explicit salt.

Pre-fix, a missing salt silently degraded HMAC to ``b""`` — the realistic
faker derivation reduced to a deterministic public hash, which meant any
attacker observing one (fake, original) pair could brute-force the rest of
the document with no entropy. v0.6.1+ raises ``ValueError`` instead.
"""

from __future__ import annotations

import pytest


def test_realistic_strategy_without_salt_raises():
    """``realistic`` config without seed/salt + no env var must raise."""
    from argus_redact import redact

    with pytest.raises(ValueError, match="realistic.*salt|salt.*realistic"):
        redact(
            "王建国的电话13912345678",
            config={"phone": {"strategy": "realistic"}},
            lang="zh",
        )


def test_pseudonym_llm_without_salt_raises():
    from argus_redact import redact_pseudonym_llm

    with pytest.raises(ValueError, match="salt"):
        redact_pseudonym_llm("王建国的电话13912345678", lang="zh")


def test_pseudonym_llm_explicit_salt_works():
    from argus_redact import redact_pseudonym_llm

    r = redact_pseudonym_llm(
        "王建国的电话13912345678",
        salt=b"explicit-32-byte-salt-padding!!",
        lang="zh",
    )
    assert r.audit_text  # no raise
    assert r.downstream_text


def test_realistic_with_seed_works():
    """``seed=<int>`` is back-compat path: provides 64-bit entropy via 8-byte BE."""
    from argus_redact import redact

    redacted, key = redact(
        "王建国的电话13912345678",
        config={"phone": {"strategy": "realistic"}},
        lang="zh",
        seed=42,
    )
    assert "13912345678" not in redacted
    assert key  # non-empty


def test_env_var_salt_works(monkeypatch):
    """``ARGUS_REDACT_PSEUDONYM_SALT`` env var fallback still works (no raise)."""
    monkeypatch.setenv("ARGUS_REDACT_PSEUDONYM_SALT", "test-env-salt-value")
    from argus_redact import redact

    redacted, key = redact(
        "王建国的电话13912345678",
        config={"phone": {"strategy": "realistic"}},
        lang="zh",
    )
    assert "13912345678" not in redacted


def test_resolve_salt_raises_with_no_inputs(monkeypatch):
    """Unit test: ``_resolve_salt`` raises when both seed and env are absent."""
    monkeypatch.delenv("ARGUS_REDACT_PSEUDONYM_SALT", raising=False)
    from argus_redact.pure.replacer import _resolve_salt

    with pytest.raises(ValueError, match="salt"):
        _resolve_salt(None)


def test_resolve_salt_returns_bytes_when_provided():
    from argus_redact.pure.replacer import _resolve_salt

    assert _resolve_salt(b"\x42" * 32) == b"\x42" * 32
    assert _resolve_salt(42) == (42).to_bytes(8, "big")
