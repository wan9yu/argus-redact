"""MCP ``_TOKEN_STORE`` enforces TTL + LRU bounds (audit H9).

Pre-fix the store was an unbounded module-level dict with no eviction —
tokens lived for the lifetime of the MCP server process. Combined with no
per-session binding, a leaked token from one MCP session could be replayed
by another consumer of the same server. v0.6.2+ adds a 5-min idle TTL and
caps the store at 100 entries (LRU).

v0.7.20+: each entry also retains the redacted prompt — ``(key, anchor,
redacted, timestamp)`` — so restore can run the supplementary injection
heuristic (H). Same TTL / LRU bound; see ``mcp_server._TOKEN_STORE``.
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
    from argus_redact.compose import make_anchor

    fake_now = [1000.0]
    monkeypatch.setattr(m, "_now", lambda: fake_now[0])

    key = {"P-001": "Alice"}
    anchor = make_anchor(key)
    token = m._create_key_token(key, anchor, "redacted prompt")
    resolved = m._resolve_key_token(token)
    assert resolved is not None
    assert resolved[0] == key

    fake_now[0] += 60 * 6  # 6 min later (> 5 min idle TTL)
    assert m._resolve_key_token(token) is None


def test_token_access_extends_ttl(monkeypatch):
    import argus_redact.integrations.mcp_server as m
    from argus_redact.compose import make_anchor

    fake_now = [1000.0]
    monkeypatch.setattr(m, "_now", lambda: fake_now[0])

    key = {"P-001": "Alice"}
    anchor = make_anchor(key)
    token = m._create_key_token(key, anchor, "redacted prompt")

    fake_now[0] += 60 * 4  # 4 min later — still alive (under TTL)
    assert m._resolve_key_token(token) is not None  # access bumps timestamp

    fake_now[0] += 60 * 4  # +4 min more — alive (last access was 4 min ago)
    assert m._resolve_key_token(token) is not None


def test_token_store_size_bounded():
    import argus_redact.integrations.mcp_server as m
    from argus_redact.compose import make_anchor

    key = {"P-1": "first"}
    first_token = m._create_key_token(key, make_anchor(key), "redacted prompt")
    # Fill above the cap
    for i in range(m._TOKEN_STORE_MAX + 50):
        k = {"P": f"v{i}"}
        m._create_key_token(k, make_anchor(k), "redacted prompt")

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


def test_store_entry_is_a_four_tuple_with_redacted_prompt():
    """v0.7.20: the store retains (key, anchor, redacted, timestamp) so restore
    can run the H heuristic — the redacted prompt (pseudonyms only) is strictly
    less sensitive than the key (pseudonym -> original) already held here, under
    the same TTL / LRU bound."""
    import argus_redact.integrations.mcp_server as m
    from argus_redact.compose import make_anchor

    key = {"P-001": "Alice"}
    anchor = make_anchor(key)
    token = m._create_key_token(key, anchor, "redacted prompt text")

    stored = m._TOKEN_STORE[token]
    assert len(stored) == 4
    assert stored[0] == key
    assert stored[1] is anchor
    assert stored[2] == "redacted prompt text"

    resolved = m._resolve_key_token(token)
    assert resolved == (key, anchor, "redacted prompt text")
