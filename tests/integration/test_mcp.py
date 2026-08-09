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

    @pytest.mark.asyncio
    async def test_should_expose_redact_tool(self, mcp_app):
        tool_names = [t.name for t in await mcp_app.list_tools()]

        assert "redact" in tool_names

    @pytest.mark.asyncio
    async def test_should_expose_restore_tool(self, mcp_app):
        tool_names = [t.name for t in await mcp_app.list_tools()]

        assert "restore" in tool_names

    @pytest.mark.asyncio
    async def test_should_expose_info_tool(self, mcp_app):
        tool_names = [t.name for t in await mcp_app.list_tools()]

        assert "info" in tool_names

    @pytest.mark.asyncio
    async def test_should_expose_assess_tool(self, mcp_app):
        tool_names = [t.name for t in await mcp_app.list_tools()]

        assert "assess" in tool_names


class TestMCPToolExecution:
    @pytest.fixture
    def mcp_app(self):
        if not HAS_MCP:
            pytest.skip("mcp not installed")
        from argus_redact.integrations.mcp_server import mcp

        return mcp

    @pytest.mark.asyncio
    async def test_should_redact_and_return_key_token(self, mcp_app):
        result = await mcp_app.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "salt": 42},
        )

        content = result.content[0].text
        data = json.loads(content)
        assert "redacted" in data
        assert "key_token" in data
        assert "13812345678" not in data["redacted"]

    @pytest.mark.asyncio
    async def test_should_restore_with_key_token(self, mcp_app):
        result = await mcp_app.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "salt": 42},
        )
        content = result.content[0].text
        data = json.loads(content)

        # Guard-by-default restore requires the anchor nonce to appear in the text.
        # Simulate an LLM response that echoes the nonce as instructed by anchor_prompt.
        # anchor_prompt contains the nonce verbatim, so appending it to the redacted
        # text is equivalent to the LLM replying with the nonce-echo line.
        text_with_nonce = data["redacted"] + "\n" + data["anchor_prompt"]

        result2 = await mcp_app.call_tool(
            "restore",
            {"text": text_with_nonce, "key_token": data["key_token"]},
        )
        content2 = result2.content[0].text
        restored = json.loads(content2)

        assert "13812345678" in restored["restored"]

    @pytest.mark.asyncio
    async def test_default_salt_is_strong_random_not_grid_searchable(self, mcp_app):
        # Without an explicit salt the server must use a strong per-call random salt
        # (CSPRNG), so a salted pseudonym code (here a location LOCA-NNNNN) is NOT
        # deterministic / grid-searchable across calls. An explicit int salt remains
        # a determinism override. Both must still redact the original.
        async def red(args):
            r = await mcp_app.call_tool("redact", args)
            return json.loads(r.content[0].text)

        a = await red({"text": "我住在西湖区", "mode": "fast"})
        b = await red({"text": "我住在西湖区", "mode": "fast"})
        assert "西湖区" not in a["redacted"] and "西湖区" not in b["redacted"]
        assert a["redacted"] != b["redacted"], (
            "default (no-salt) output must be non-deterministic — a strong random "
            "salt, not the library's grid-searchable salt=None default"
        )

        c1 = await red({"text": "我住在西湖区", "mode": "fast", "salt": 42})
        c2 = await red({"text": "我住在西湖区", "mode": "fast", "salt": 42})
        assert c1["redacted"] == c2["redacted"], "explicit salt must stay deterministic"

    @pytest.mark.asyncio
    async def test_should_assess_and_return_entities_found(self, mcp_app):
        # Phone number guarantees at least one entity; entities_found must match
        # the actual detection count (non-vacuous: would fail if assess broke or
        # stats["total"] silently returned 0 instead of raising on a missing key).
        text = "联系电话：13812345678"
        result = await mcp_app.call_tool(
            "assess",
            {"text": text, "mode": "fast"},
        )

        content = result.content[0].text
        data = json.loads(content)

        assert "entities_found" in data
        assert data["entities_found"] > 0, (
            "expected at least one entity for a phone-number input, got 0 — "
            "assess may be broken or entities_found is silently defaulting"
        )
        assert "risk" in data

        # Cross-check: entities_found must equal what redact() actually counted
        from argus_redact.glue.redact import redact

        report = redact(text, lang="zh", mode="fast", report=True)
        assert data["entities_found"] == report.stats["total"]

    @pytest.mark.asyncio
    async def test_should_return_info(self, mcp_app):
        result = await mcp_app.call_tool("info", {})

        content = result.content[0].text
        assert "argus-redact" in content or "version" in content

    @pytest.mark.asyncio
    async def test_redact_trailing_comma_lang_does_not_crash(self, mcp_app):
        """F6 — a trailing comma in lang (e.g. "zh,") used to leave an empty
        string segment in the split list, which _load_patterns/_validate_langs
        rejected as an unknown language code. The empty segment must be
        filtered out."""
        result = await mcp_app.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "lang": "zh,", "salt": 42},
        )

        content = result.content[0].text
        data = json.loads(content)
        assert "13812345678" not in data["redacted"]

    @pytest.mark.asyncio
    async def test_redact_multi_lang_csv_still_works(self, mcp_app):
        """Positive control: a genuine multi-lang CSV (no empty segment)
        still works after the fix."""
        result = await mcp_app.call_tool(
            "redact",
            {"text": "电话13812345678", "mode": "fast", "lang": "zh,en", "salt": 42},
        )

        content = result.content[0].text
        data = json.loads(content)
        assert "13812345678" not in data["redacted"]

    @pytest.mark.asyncio
    async def test_redact_all_separator_lang_raises_clean_error(self, mcp_app):
        """A lang of only separators (e.g. ",") splits down to an empty list.
        Before the central empty-lang guard, redact()'s report/anchor lang[0]
        raised IndexError — an internal 500 over the wire. It must now surface
        as the clean 'No language specified' ValueError (a 400-class error),
        never a raw index crash."""
        with pytest.raises(Exception) as exc_info:
            await mcp_app.call_tool(
                "redact",
                {"text": "电话13812345678", "mode": "fast", "lang": ",", "salt": 42},
            )
        message = str(exc_info.value)
        assert "No language specified" in message
        assert "index out of range" not in message

    @pytest.mark.asyncio
    async def test_assess_trailing_comma_lang_does_not_crash(self, mcp_app):
        """F6 — same empty-segment fix applies to the assess tool's lang split."""
        result = await mcp_app.call_tool(
            "assess",
            {"text": "联系电话：13812345678", "mode": "fast", "lang": "zh,"},
        )

        content = result.content[0].text
        data = json.loads(content)
        assert data["entities_found"] > 0

    @pytest.mark.asyncio
    async def test_assess_envelope_carries_no_plaintext_anywhere(self, mcp_app):
        """Envelope-scoped, not field-scoped.

        Every other plaintext-absence assertion in this suite indexes one key
        (`data["redacted"]`), so an original leaking through `entities`, a risk
        `reason`, or a security event's `detail` would pass all of them.
        """
        result = await mcp_app.call_tool(
            "assess",
            {"text": "请联系张伟，电话 13812345678。", "lang": "zh", "mode": "fast"},
        )
        envelope = result.content[0].text
        assert "13812345678" not in envelope
        assert "张伟" not in envelope
