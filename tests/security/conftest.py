"""Shared fixtures for the security test suite.

The autouse env-clear ensures every test runs without ``ARGUS_REDACT_PSEUDONYM_SALT``
poisoning the no-salt branches; ``test_salt`` is the canonical 32-byte salt
for any test that needs an explicit one.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def test_salt() -> bytes:
    return b"argus-redact-security-test-salt!"


@pytest.fixture(autouse=True)
def _clear_pseudonym_salt_env(monkeypatch):
    monkeypatch.delenv("ARGUS_REDACT_PSEUDONYM_SALT", raising=False)
