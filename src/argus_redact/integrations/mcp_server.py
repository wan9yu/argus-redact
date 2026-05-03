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
import secrets
import time
from collections import OrderedDict

from mcp.server.fastmcp import FastMCP

from argus_redact import RedactReport, __version__, redact, restore

mcp = FastMCP("argus-redact")


# Process-scoped token store with idle TTL + LRU bound (v0.6.2+).
# Pre-fix the store was unbounded and tokens never expired — combined with
# no per-session binding, a leaked token could be replayed indefinitely.
# Per-session binding is a v0.7+ candidate (requires FastMCP API survey).
_TOKEN_TTL_SECONDS = 5 * 60
_TOKEN_STORE_MAX = 100
_TOKEN_STORE: "OrderedDict[str, tuple[dict, float]]" = OrderedDict()


def _now() -> float:
    """Wrapped for monkeypatch in tests; ``time.monotonic`` is robust to
    system clock adjustments."""
    return time.monotonic()


def _create_key_token(key: dict) -> str:
    """Mint a 128-bit URL-safe token referencing this key dict.

    Evicts the oldest entry when the store exceeds ``_TOKEN_STORE_MAX``
    (LRU). Tokens themselves expire ``_TOKEN_TTL_SECONDS`` after their
    last access — see ``_resolve_key_token``.
    """
    token = secrets.token_urlsafe(16)
    # Fresh token (token_urlsafe collisions are astronomically improbable) —
    # OrderedDict insertion places at end automatically; no move_to_end needed.
    _TOKEN_STORE[token] = (key, _now())
    while len(_TOKEN_STORE) > _TOKEN_STORE_MAX:
        _TOKEN_STORE.popitem(last=False)
    return token


def _resolve_key_token(token: str) -> dict | None:
    """Look up a key dict by token, returning ``None`` if absent or expired.

    Successful lookup bumps the entry's timestamp (sliding-window TTL).
    """
    entry = _TOKEN_STORE.get(token)
    if entry is None:
        return None
    key, ts = entry
    if _now() - ts > _TOKEN_TTL_SECONDS:
        del _TOKEN_STORE[token]
        return None
    _TOKEN_STORE[token] = (key, _now())
    _TOKEN_STORE.move_to_end(token)
    return key


@mcp.tool(name="redact")
async def redact_text(
    text: str,
    lang: str = "zh",
    mode: str = "fast",
    seed: int | None = None,
) -> str:
    """Redact PII from text. Returns JSON with redacted text and a key_token.

    Args:
        text: Input text containing PII to redact.
        lang: Language code(s). Use comma-separated for multiple: "zh,en".
        mode: Detection mode — "fast" (regex), "ner" (regex+NER), "auto" (all).
        seed: Random seed for deterministic output (testing only).

    Returns JSON with two fields:
    - ``redacted``: redacted text
    - ``key_token``: short-lived token (process-scoped); pass to restore tool
      to recover the original. The raw key never enters the LLM's context.
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
    token = _create_key_token(key)
    return json.dumps(
        {"redacted": redacted_text, "key_token": token},
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool(name="restore")
async def restore_text(
    text: str,
    key_token: str = "",
) -> str:
    """Restore redacted text using a key_token returned by the redact tool.

    Args:
        text: Redacted text (e.g. LLM output containing pseudonyms).
        key_token: Token returned by the redact tool. Tokens are scoped to
            the MCP server process; restart invalidates them.
    """
    if not key_token:
        raise ValueError("Must provide key_token (returned by the redact tool)")

    key_dict = _resolve_key_token(key_token)
    if key_dict is None:
        raise ValueError(
            "Token not found or expired (process restarted?). "
            "Re-run redact to obtain a fresh key_token."
        )

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
