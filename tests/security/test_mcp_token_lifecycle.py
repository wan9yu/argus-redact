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


class TestTokenStoreConcurrency:
    """The store is a plain module-level ``OrderedDict`` reachable from every
    concurrent MCP tool call. Both mutating paths had a check-then-act window:

    - ``_resolve_key_token``: two callers on the same EXPIRED token both pass
      the TTL check and both ``del`` it; the loser gets a raw ``KeyError`` out
      of an internal helper instead of the intended ``None`` -> clean
      ``ValueError("Token not found or expired")``. Wrong failure mode escaping
      to the MCP protocol caller, exactly what a retry-happy client produces.
    - ``_create_key_token``: the LRU drain ``while len(...) > MAX:
      popitem(last=False)`` can raise ``KeyError`` on a store another thread
      already emptied.
    """

    @staticmethod
    def _hammer(target, threads=32):
        import threading

        barrier = threading.Barrier(threads)
        errors = []

        def worker():
            barrier.wait()
            try:
                target()
            except Exception as exc:  # noqa: BLE001 — any escape is the defect
                errors.append(repr(exc))

        pool = [threading.Thread(target=worker) for _ in range(threads)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()
        return errors

    def test_concurrent_resolve_of_an_expired_token_never_raises(self, monkeypatch):
        import sys

        import argus_redact.integrations.mcp_server as m

        monkeypatch.setattr(sys, "setswitchinterval", sys.setswitchinterval)
        original = sys.getswitchinterval()
        sys.setswitchinterval(1e-9)  # widen the check-then-act window
        try:
            errors = []
            for _ in range(200):
                m._TOKEN_STORE.clear()
                token = m._create_key_token({"P-1": "Alice"}, None, "P-1")
                key, anchor, redacted, _ts = m._TOKEN_STORE[token]
                m._TOKEN_STORE[token] = (
                    key,
                    anchor,
                    redacted,
                    m._now() - 10 * m._TOKEN_TTL_SECONDS,  # pre-expired
                )
                errors += self._hammer(lambda: m._resolve_key_token(token))
        finally:
            sys.setswitchinterval(original)
        assert errors == [], f"raw exceptions escaped _resolve_key_token: {errors[:3]}"

    def test_concurrent_mint_never_raises_and_respects_the_bound(self):
        import sys

        import argus_redact.integrations.mcp_server as m

        original = sys.getswitchinterval()
        sys.setswitchinterval(1e-9)
        try:
            m._TOKEN_STORE.clear()
            errors = []
            for _ in range(20):
                errors += self._hammer(lambda: m._create_key_token({"P-1": "Alice"}, None, "P-1"))
        finally:
            sys.setswitchinterval(original)
        assert errors == [], f"raw exceptions escaped _create_key_token: {errors[:3]}"
        assert len(m._TOKEN_STORE) <= m._TOKEN_STORE_MAX


def test_restore_tool_docstring_names_lru_eviction_as_an_invalidation_cause():
    """The bound is process-GLOBAL, so a busy neighbour session can evict this
    session's key — an MCP client sees a token that was valid a moment ago stop
    resolving. The docstring named only process restart, so the one failure mode
    a client can actually mitigate (by re-running redact, or by not exceeding
    the bound) was undocumented."""
    import argus_redact.integrations.mcp_server as m

    doc = m.restore_text.__doc__ or ""
    combined = doc + (m.restore_text.fn.__doc__ or "") if hasattr(m.restore_text, "fn") else doc
    assert "evict" in combined.lower(), (
        "restore tool docstring must name LRU eviction, not just process restart"
    )
    assert str(m._TOKEN_STORE_MAX) in combined, (
        "restore tool docstring must state the concurrent-session bound"
    )
