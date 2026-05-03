"""MCP ``_TOKEN_STORE`` enforces TTL + LRU bounds (audit H9).

Pre-fix the store was an unbounded module-level dict with no eviction —
tokens lived for the lifetime of the MCP server process. Combined with no
per-session binding, a leaked token from one MCP session could be replayed
by another consumer of the same server. v0.6.2+ adds a 5-min idle TTL and
caps the store at 100 entries (LRU).
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_store():
    """Each test starts with an empty token store."""
    pytest.importorskip("mcp", reason="mcp not installed")
    import argus_redact.integrations.mcp_server as m

    m._TOKEN_STORE.clear()
    yield
    m._TOKEN_STORE.clear()


def test_token_evicts_after_idle_ttl(monkeypatch):
    import argus_redact.integrations.mcp_server as m

    fake_now = [1000.0]
    monkeypatch.setattr(m, "_now", lambda: fake_now[0])

    token = m._create_key_token({"P-001": "Alice"})
    assert m._resolve_key_token(token) == {"P-001": "Alice"}

    fake_now[0] += 60 * 6  # 6 min later (> 5 min idle TTL)
    assert m._resolve_key_token(token) is None


def test_token_access_extends_ttl(monkeypatch):
    import argus_redact.integrations.mcp_server as m

    fake_now = [1000.0]
    monkeypatch.setattr(m, "_now", lambda: fake_now[0])

    token = m._create_key_token({"P-001": "Alice"})

    fake_now[0] += 60 * 4  # 4 min later — still alive (under TTL)
    assert m._resolve_key_token(token) is not None  # access bumps timestamp

    fake_now[0] += 60 * 4  # +4 min more — alive (last access was 4 min ago)
    assert m._resolve_key_token(token) is not None


def test_token_store_size_bounded():
    import argus_redact.integrations.mcp_server as m

    first_token = m._create_key_token({"P-1": "first"})
    # Fill above the cap
    for i in range(m._TOKEN_STORE_MAX + 50):
        m._create_key_token({"P": f"v{i}"})

    assert m._resolve_key_token(first_token) is None  # evicted by LRU
    assert len(m._TOKEN_STORE) == m._TOKEN_STORE_MAX


def test_resolve_unknown_token_returns_none():
    import argus_redact.integrations.mcp_server as m

    assert m._resolve_key_token("nonexistent-token") is None


def test_token_store_constants_set():
    """TTL and max are documented module-level constants."""
    import argus_redact.integrations.mcp_server as m

    assert m._TOKEN_TTL_SECONDS == 5 * 60
    assert m._TOKEN_STORE_MAX == 100
