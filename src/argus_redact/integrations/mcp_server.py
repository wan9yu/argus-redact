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
from argus_redact.compose import make_anchor, prompt_anchor

mcp = FastMCP("argus-redact")


# Process-scoped token store with idle TTL + LRU bound (v0.6.2+).
# Pre-fix the store was unbounded and tokens never expired — combined with
# no per-session binding, a leaked token could be replayed indefinitely.
# Per-session binding is a v0.7+ candidate (requires FastMCP API survey).
#
# Each entry now holds (key, anchor, timestamp) — the anchor carries the
# per-call nonce and scope for guard-by-default restore (Theme A).
_TOKEN_TTL_SECONDS = 5 * 60
_TOKEN_STORE_MAX = 100
# OrderedDict values: tuple[dict, Anchor | None, float]
_TOKEN_STORE: "OrderedDict[str, tuple[dict, object, float]]" = OrderedDict()


def _now() -> float:
    """Wrapped for monkeypatch in tests; ``time.monotonic`` is robust to
    system clock adjustments."""
    return time.monotonic()


def _create_key_token(key: dict, anchor: object) -> str:
    """Mint a 128-bit URL-safe token referencing this key dict and anchor.

    Evicts the oldest entry when the store exceeds ``_TOKEN_STORE_MAX``
    (LRU). Tokens themselves expire ``_TOKEN_TTL_SECONDS`` after their
    last access — see ``_resolve_key_token``.
    """
    token = secrets.token_urlsafe(16)
    # Fresh token — OrderedDict insertion places at end automatically.
    _TOKEN_STORE[token] = (key, anchor, _now())
    while len(_TOKEN_STORE) > _TOKEN_STORE_MAX:
        _TOKEN_STORE.popitem(last=False)
    return token


def _resolve_key_token(token: str) -> tuple[dict, object] | None:
    """Look up a (key, anchor) pair by token, returning ``None`` if absent or expired.

    Successful lookup bumps the entry's timestamp (sliding-window TTL).
    """
    entry = _TOKEN_STORE.get(token)
    if entry is None:
        return None
    key, anchor, ts = entry
    if _now() - ts > _TOKEN_TTL_SECONDS:
        del _TOKEN_STORE[token]
        return None
    _TOKEN_STORE[token] = (key, anchor, _now())
    _TOKEN_STORE.move_to_end(token)
    return key, anchor


@mcp.tool(name="redact")
async def redact_text(
    text: str,
    lang: str = "zh",
    mode: str = "fast",
    salt: int | None = None,
) -> str:
    """Redact PII from text. Returns JSON with redacted text, a key_token, and anchor_prompt.

    Args:
        text: Input text containing PII to redact.
        lang: Language code(s). Use comma-separated for multiple: "zh,en".
        mode: Detection mode — "fast" (regex), "ner" (regex+NER), "auto" (all).
        salt: Optional int to FORCE deterministic output — testing only. An int
            salt is low-entropy and grid-searchable, so omit it in production:
            when absent, the server uses a strong per-call random salt (CSPRNG,
            equivalent to ``os.urandom(32)``) so pseudonym codes are not
            grid-searchable or linkable across calls. (MCP args are JSON, so bytes
            cannot be passed here.)

    Returns JSON with three fields:
    - ``redacted``: redacted text
    - ``key_token``: short-lived token (process-scoped); pass to restore tool
      to recover the original. The raw key never enters the LLM's context.
    - ``anchor_prompt``: system-prompt addendum to inject before the LLM call;
      it embeds the nonce-echo instruction so guard-by-default restore can verify
      the response. Pass as a system message to the LLM. Empty string when no PII
      was detected.
    """
    lang_param: str | list[str] = lang
    if "," in lang:
        lang_param = [code.strip() for code in lang.split(",")]

    # No explicit salt → strong per-call random salt (CSPRNG). Making the
    # CSPRNG explicit here keeps this tool's security boundary auditable:
    # salt=None already triggers non-deterministic per-call codes in the
    # library, and the explicit token_bytes(32) documents that intent clearly.
    # An explicit int salt forces determinism — testing only; low-entropy
    # ints are grid-searchable on small PII domains.
    effective_salt: int | bytes = salt if salt is not None else secrets.token_bytes(32)

    redacted_text, key = redact(
        text,
        lang=lang_param,
        mode=mode,
        salt=effective_salt,
    )
    anchor = make_anchor(key)
    token = _create_key_token(key, anchor)

    # Build the system-prompt addendum; use the lang string (first code if CSV)
    prompt_lang = lang_param if isinstance(lang_param, str) else lang_param[0]
    addendum = prompt_anchor(key, prompt_lang, anchor=anchor)

    return json.dumps(
        {"redacted": redacted_text, "key_token": token, "anchor_prompt": addendum},
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool(name="restore")
async def restore_text(
    text: str,
    key_token: str = "",
) -> str:
    """Restore redacted text using a key_token returned by the redact tool.

    The restore tool uses guard-by-default: the LLM response must contain the
    nonce embedded in the ``anchor_prompt`` returned by redact. If the nonce is
    absent (e.g. a forged or injected response), restore is fail-closed and
    returns the un-restored text with a ``security_events`` field.

    Args:
        text: Redacted text (e.g. LLM output containing pseudonyms).
        key_token: Token returned by the redact tool. Tokens are scoped to
            the MCP server process; restart invalidates them.
    """
    if not key_token:
        raise ValueError("Must provide key_token (returned by the redact tool)")

    resolved = _resolve_key_token(key_token)
    if resolved is None:
        raise ValueError(
            "Token not found or expired (process restarted?). "
            "Re-run redact to obtain a fresh key_token."
        )

    key_dict, anchor = resolved
    restored, details = restore(text, key_dict, guard=True, anchor=anchor, detailed=True)
    events = details.get("security_events", [])

    payload: dict = {"restored": restored}
    if events:
        payload["security_events"] = events
    return json.dumps(payload, ensure_ascii=False)


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
            # redact() always sets stats["total"] — contract pinned by test_mcp.py
            "entities_found": report.stats["total"],
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

    from argus_redact.glue.redact import _LANG_DISPLAY_NAMES, _LANG_PATTERNS
    from argus_redact.lang.shared.patterns import PATTERNS as SHARED

    lang_info = {}

    for code in _LANG_PATTERNS:
        mod_code = "in_" if code == "in" else code
        try:
            mod = importlib.import_module(f"argus_redact.lang.{mod_code}.patterns")
            count = len(mod.PATTERNS) + len(SHARED)
        except ModuleNotFoundError:
            count = 0
        has_ner = importlib.util.find_spec(f"argus_redact.lang.{mod_code}.ner_adapter") is not None
        lang_info[code] = {
            "name": _LANG_DISPLAY_NAMES.get(code, code),
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
