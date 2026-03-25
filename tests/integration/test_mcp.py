"""Tests for MCP server — verify tools are exposed correctly."""

import importlib.util
import json

import pytest

HAS_MCP = importlib.util.find_spec("mcp") is not None

pytestmark = pytest.mark.slow


class TestMCPServer:
    @pytest.fixture
    def mcp_app(self):
        if not HAS_MCP:
            pytest.skip("mcp not installed")
        from argus_redact.integrations.mcp_server import mcp

        return mcp

    def test_should_expose_redact_tool(self, mcp_app):
        tool_names = [t.name for t in mcp_app._tool_manager.list_tools()]

        assert "redact" in tool_names

    def test_should_expose_restore_tool(self, mcp_app):
        tool_names = [t.name for t in mcp_app._tool_manager.list_tools()]

        assert "restore" in tool_names

    def test_should_expose_info_tool(self, mcp_app):
        tool_names = [t.name for t in mcp_app._tool_manager.list_tools()]

        assert "info" in tool_names


class TestMCPToolExecution:
    @pytest.fixture
    def mcp_app(self):
        if not HAS_MCP:
            pytest.skip("mcp not installed")
        from argus_redact.integrations.mcp_server import mcp

        return mcp

    @pytest.mark.asyncio
    async def test_should_redact_and_return_key(self, mcp_app):
        result = await mcp_app._tool_manager.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "seed": 42},
        )

        content = result if isinstance(result, str) else result[0].text
        data = json.loads(content)
        assert "redacted" in data
        assert "key" in data
        assert "13812345678" not in data["redacted"]

    @pytest.mark.asyncio
    async def test_should_restore_with_key(self, mcp_app):
        result = await mcp_app._tool_manager.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "seed": 42},
        )
        content = result if isinstance(result, str) else result[0].text
        data = json.loads(content)

        result2 = await mcp_app._tool_manager.call_tool(
            "restore",
            {"text": data["redacted"], "key": json.dumps(data["key"])},
        )
        content2 = result2 if isinstance(result2, str) else result2[0].text
        restored = json.loads(content2)

        assert "13812345678" in restored["restored"]

    @pytest.mark.asyncio
    async def test_should_return_info(self, mcp_app):
        result = await mcp_app._tool_manager.call_tool("info", {})

        content = result if isinstance(result, str) else result[0].text
        assert "argus-redact" in content or "version" in content
