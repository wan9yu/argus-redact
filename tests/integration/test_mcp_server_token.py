"""v0.5.5: MCP server returns ONLY key_token (raw key field removed).

The deprecation period started in v0.5.4 and ends here — the raw `key`
field is gone from the redact response, and the `key` parameter is gone
from the restore tool.
"""

import importlib.util
import json

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


class TestRedactToolReturnsOnlyToken:
    @pytest.mark.asyncio
    async def test_should_return_key_token(self, mcp_app):
        result = await mcp_app._tool_manager.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "seed": 42},
        )
        content = result if isinstance(result, str) else result[0].text
        data = json.loads(content)
        assert "redacted" in data
        assert "key_token" in data, "key_token is the v0.5.4+ secure path"
        assert isinstance(data["key_token"], str) and len(data["key_token"]) > 10

    @pytest.mark.asyncio
    async def test_redact_response_no_longer_has_key_field(self, mcp_app):
        # Regression guard: the deprecated raw `key` field was removed in v0.5.5.
        result = await mcp_app._tool_manager.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "seed": 42},
        )
        content = result if isinstance(result, str) else result[0].text
        data = json.loads(content)
        assert "key" not in data, (
            "raw `key` was removed in v0.5.5 (deprecated v0.5.4); "
            "callers must use key_token"
        )


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
    async def test_should_raise_when_token_unknown(self, mcp_app):
        with pytest.raises(Exception) as exc:
            await mcp_app._tool_manager.call_tool(
                "restore",
                {"text": "x", "key_token": "this-token-does-not-exist"},
            )
        assert "token" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_should_raise_when_no_token(self, mcp_app):
        with pytest.raises(Exception) as exc:
            await mcp_app._tool_manager.call_tool("restore", {"text": "x"})
        assert "key_token" in str(exc.value).lower() or "token" in str(exc.value).lower()


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
