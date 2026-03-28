"""argus-redact MCP Server — expose redact/restore as MCP tools.

Usage:
    python -m argus_redact.integrations.mcp_server

Configure in Claude Desktop (~/Library/Application Support/Claude/claude_desktop_config.json):
    {
      "mcpServers": {
        "argus-redact": {
          "command": "python",
          "args": ["-m", "argus_redact.integrations.mcp_server"]
        }
      }
    }
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from argus_redact import RedactReport, __version__, redact, restore

mcp = FastMCP("argus-redact")


@mcp.tool(name="redact")
async def redact_text(
    text: str,
    lang: str = "zh",
    mode: str = "fast",
    seed: int | None = None,
) -> str:
    """Redact PII from text. Returns JSON with redacted text and key.

    Args:
        text: Input text containing PII to redact.
        lang: Language code(s). Use comma-separated for multiple: "zh,en".
        mode: Detection mode — "fast" (regex), "ner" (regex+NER), "auto" (all).
        seed: Random seed for deterministic output (testing only).
    """
    lang_param: str | list[str] = lang
    if "," in lang:
        lang_param = [code.strip() for code in lang.split(",")]

    redacted_text, key = redact(
        text,
        lang=lang_param,
        mode=mode,
        seed=seed,
    )

    return json.dumps(
        {"redacted": redacted_text, "key": key},
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool(name="restore")
async def restore_text(text: str, key: str) -> str:
    """Restore redacted text using a key from a previous redact call.

    Args:
        text: Redacted text (e.g. LLM output containing pseudonyms).
        key: JSON string of the key dict from redact.
    """
    key_dict = json.loads(key)
    restored = restore(text, key_dict)

    return json.dumps(
        {"restored": restored},
        ensure_ascii=False,
    )


@mcp.tool(name="assess")
async def assess_text(
    text: str,
    lang: str = "zh",
    mode: str = "fast",
) -> str:
    """Assess privacy risk of text. Returns risk score, level, reasons, and PIPL articles.

    Args:
        text: Input text to assess for privacy risk.
        lang: Language code(s). Use comma-separated for multiple: "zh,en".
        mode: Detection mode — "fast" (regex), "ner" (regex+NER), "auto" (all).
    """
    lang_param: str | list[str] = lang
    if "," in lang:
        lang_param = [code.strip() for code in lang.split(",")]

    report: RedactReport = redact(
        text,
        lang=lang_param,
        mode=mode,
        report=True,
    )

    return json.dumps(
        {
            "risk": {
                "score": report.risk.score,
                "level": report.risk.level,
                "reasons": list(report.risk.reasons),
                "pipl_articles": list(report.risk.pipl_articles),
            },
            "entities_found": report.stats.get("total", 0),
            "redacted": report.redacted_text,
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool(name="info")
async def redact_info() -> str:
    """Show argus-redact version and installed capabilities."""
    import importlib
    import importlib.util

    from argus_redact.lang.shared.patterns import PATTERNS as SHARED

    langs = {
        "zh": "Chinese",
        "en": "English",
        "ja": "Japanese",
        "ko": "Korean",
        "de": "German",
        "uk": "British English",
        "in": "Indian",
        "br": "Brazilian Portuguese",
    }
    lang_info = {}

    for code, name in langs.items():
        mod_code = "in_" if code == "in" else code
        try:
            mod = importlib.import_module(f"argus_redact.lang.{mod_code}.patterns")
            count = len(mod.PATTERNS) + len(SHARED)
        except ModuleNotFoundError:
            count = 0
        has_ner = importlib.util.find_spec(f"argus_redact.lang.{mod_code}.ner_adapter") is not None
        lang_info[code] = {
            "name": name,
            "patterns": count,
            "ner": has_ner,
        }

    return json.dumps(
        {
            "version": __version__,
            "languages": lang_info,
        },
        ensure_ascii=False,
        indent=2,
    )


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
