"""v0.5.4: MCP server returns key_token alongside deprecated raw key.

Tests cover the deprecation path: v0.5.4 dual-return + DeprecationWarning,
v0.5.5 will remove the raw `key` field entirely.
"""

import importlib.util
import json
import warnings

import pytest

HAS_MCP = importlib.util.find_spec("mcp") is not None

pytestmark = pytest.mark.slow


@pytest.fixture
def mcp_app():
    if not HAS_MCP:
        pytest.skip("mcp not installed")
    from argus_redact.integrations.mcp_server import (
        _TOKEN_STORE,
        mcp,
    )

    _TOKEN_STORE.clear()  # isolate tests
    return mcp


class TestRedactToolReturnsTokenAndDeprecatedKey:
    @pytest.mark.asyncio
    async def test_should_return_both_key_and_key_token(self, mcp_app):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = await mcp_app._tool_manager.call_tool(
                "redact",
                {"text": "电话13812345678", "mode": "fast", "seed": 42},
            )
        content = result if isinstance(result, str) else result[0].text
        data = json.loads(content)
        assert "redacted" in data
        assert "key" in data, "raw key still present in v0.5.4 (deprecation period)"
        assert "key_token" in data, "key_token added in v0.5.4"
        assert isinstance(data["key_token"], str) and len(data["key_token"]) > 10
        # DeprecationWarning emitted
        assert any(
            issubclass(w.category, DeprecationWarning) and "key" in str(w.message).lower()
            for w in caught
        ), "expected DeprecationWarning for raw key"


class TestRestoreToolViaToken:
    @pytest.mark.asyncio
    async def test_should_round_trip_via_key_token(self, mcp_app):
        result = await mcp_app._tool_manager.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "seed": 42},
        )
        data = json.loads(result if isinstance(result, str) else result[0].text)

        result2 = await mcp_app._tool_manager.call_tool(
            "restore",
            {"text": data["redacted"], "key_token": data["key_token"]},
        )
        restored = json.loads(result2 if isinstance(result2, str) else result2[0].text)
        assert "13812345678" in restored["restored"]

    @pytest.mark.asyncio
    async def test_should_warn_when_using_legacy_key(self, mcp_app):
        result = await mcp_app._tool_manager.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "seed": 42},
        )
        data = json.loads(result if isinstance(result, str) else result[0].text)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result2 = await mcp_app._tool_manager.call_tool(
                "restore",
                {"text": data["redacted"], "key": json.dumps(data["key"])},
            )
        restored = json.loads(result2 if isinstance(result2, str) else result2[0].text)
        assert "13812345678" in restored["restored"]
        assert any(
            issubclass(w.category, DeprecationWarning) for w in caught
        ), "legacy key path should warn"

    @pytest.mark.asyncio
    async def test_should_raise_when_token_unknown(self, mcp_app):
        with pytest.raises(Exception) as exc:
            await mcp_app._tool_manager.call_tool(
                "restore",
                {"text": "x", "key_token": "this-token-does-not-exist"},
            )
        assert "token" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_should_raise_when_neither_key_nor_token(self, mcp_app):
        with pytest.raises(Exception) as exc:
            await mcp_app._tool_manager.call_tool("restore", {"text": "x"})
        # Either ValueError or FastMCP wraps it; either way the message mentions both
        assert "key" in str(exc.value).lower() or "key_token" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_should_raise_when_both_key_and_token_given(self, mcp_app):
        result = await mcp_app._tool_manager.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "seed": 42},
        )
        data = json.loads(result if isinstance(result, str) else result[0].text)

        with pytest.raises(Exception) as exc:
            await mcp_app._tool_manager.call_tool(
                "restore",
                {
                    "text": data["redacted"],
                    "key": json.dumps(data["key"]),
                    "key_token": data["key_token"],
                },
            )
        assert "mutually exclusive" in str(exc.value).lower()


class TestTokenStoreLifecycle:
    @pytest.mark.asyncio
    async def test_token_persists_within_process(self, mcp_app):
        from argus_redact.integrations.mcp_server import _TOKEN_STORE

        result = await mcp_app._tool_manager.call_tool(
            "redact",
            {"text": "phone 13812345678", "mode": "fast", "seed": 42},
        )
        data = json.loads(result if isinstance(result, str) else result[0].text)
        assert data["key_token"] in _TOKEN_STORE
