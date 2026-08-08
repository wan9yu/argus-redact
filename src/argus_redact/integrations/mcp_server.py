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
import threading
import time
from collections import OrderedDict

from mcp.server import MCPServer

from argus_redact import RedactReport, __version__, redact
from argus_redact.compose import make_anchor, prompt_anchor
from argus_redact.glue.guarded_restore import guarded_restore
from argus_redact.pure.wire import common_report_fields, risk_payload

mcp = MCPServer("argus-redact")


# Process-scoped token store with idle TTL + LRU bound (v0.6.2+).
# Pre-fix the store was unbounded and tokens never expired — combined with
# no per-session binding, a leaked token could be replayed indefinitely.
# Per-session binding is a v0.7+ candidate (requires MCPServer API survey).
#
_TOKEN_TTL_SECONDS = 5 * 60
_TOKEN_STORE_MAX = 100
# Each entry holds (key, anchor, redacted_prompt, created_at). The anchor carries the
# per-call nonce and scope for guard-by-default restore (Theme A); the redacted prompt
# lets restore run the supplementary injection heuristic (H) — it holds PSEUDONYMS
# ONLY. The store already retains `key`, which maps pseudonym -> ORIGINAL, so retaining
# it is strictly less sensitive than what is already here, under the same TTL / LRU
# bound.
_TOKEN_STORE: "OrderedDict[str, tuple[dict, object, str, float]]" = OrderedDict()

# Both store mutators are check-then-act sequences over a module-level dict that
# every concurrent MCP tool call reaches. Unlocked, `_resolve_key_token`'s
# expiry branch lets two callers on the same expired token both pass the TTL
# check and both `del` it — the loser gets a raw KeyError out of an internal
# helper instead of the intended None -> clean ValueError, and that KeyError
# escapes to the MCP protocol caller. `_create_key_token`'s LRU drain has the
# same shape (`popitem` on a store another thread just emptied). One lock over
# both keeps the TTL check, the eviction and the timestamp bump atomic. It is
# held only across dict operations — never across a redact/restore call.
_TOKEN_LOCK = threading.Lock()


def _now() -> float:
    """Wrapped for monkeypatch in tests; ``time.monotonic`` is robust to
    system clock adjustments."""
    return time.monotonic()


def _create_key_token(key: dict, anchor: object, redacted: str) -> str:
    """Mint a 128-bit URL-safe token referencing this key dict, anchor, and
    the redacted prompt.

    Evicts the oldest entry when the store exceeds ``_TOKEN_STORE_MAX``
    (LRU). Tokens themselves expire ``_TOKEN_TTL_SECONDS`` after their
    last access — see ``_resolve_key_token``.

    The bound is process-GLOBAL: a busy session can evict a quieter one's
    still-valid token. Surfaced in the ``restore`` tool docstring so a client
    knows the failure mode.
    """
    token = secrets.token_urlsafe(16)
    with _TOKEN_LOCK:  # see _TOKEN_LOCK: insert + drain must be atomic together
        # Fresh token — OrderedDict insertion places at end automatically.
        _TOKEN_STORE[token] = (key, anchor, redacted, _now())
        while len(_TOKEN_STORE) > _TOKEN_STORE_MAX:
            _TOKEN_STORE.popitem(last=False)
    return token


def _resolve_key_token(token: str) -> tuple[dict, object, str] | None:
    """Look up a (key, anchor, redacted) triple by token, returning ``None``
    if absent or expired.

    Successful lookup bumps the entry's timestamp (sliding-window TTL).

    Absent/expired is reported as ``None`` — never as an exception out of this
    helper. Two concurrent calls on the same expired token must BOTH get
    ``None`` and the caller's clean ``ValueError``; see ``_TOKEN_LOCK``.
    """
    with _TOKEN_LOCK:
        entry = _TOKEN_STORE.get(token)
        if entry is None:
            return None
        key, anchor, redacted, ts = entry
        if _now() - ts > _TOKEN_TTL_SECONDS:
            # pop(..., None), not del: a concurrent expiry of the same token
            # would otherwise raise KeyError out of this helper.
            _TOKEN_STORE.pop(token, None)
            return None
        _TOKEN_STORE[token] = (key, anchor, redacted, _now())
        _TOKEN_STORE.move_to_end(token)
        return key, anchor, redacted


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
        lang_param = [code.strip() for code in lang.split(",") if code.strip()]

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
    token = _create_key_token(key, anchor, redacted_text)

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
    strict: bool = False,
) -> str:
    """Restore redacted text using a key_token returned by the redact tool.

    The restore tool uses guard-by-default: the LLM response must contain the
    nonce embedded in the ``anchor_prompt`` returned by redact. If the nonce is
    absent (e.g. a forged or injected response), restore is fail-closed and
    returns the un-restored text with a ``security_events`` field. The redacted
    prompt retained alongside the token (pseudonyms only) also lets restore run
    the supplementary injection heuristic (H) — advisory, surfaced as a
    ``SecurityWarning`` and in ``security_events``.

    Args:
        text: Redacted text (e.g. LLM output containing pseudonyms).
        key_token: Token returned by the redact tool. Tokens are scoped to
            the MCP server process and invalidated by THREE things, all of
            which make the original unrecoverable: a process restart, the
            5-minute idle TTL, and LRU eviction. The eviction bound is 100
            entries and is process-GLOBAL, not per session — beyond ~100
            concurrent sessions a busy neighbour evicts this session's key
            even though it never expired. Redact again to mint a fresh token;
            do not hold one across a long think.
        strict: When True, raise instead of returning on ANY security event —
            covers BOTH the deterministic guard (P/S) and a suspected
            injection (H). An ordinary tool argument (JSON bool), not a
            return-shape concern — H stays advisory by default; this is the
            opt-in fail-closed path.
    """
    if not key_token:
        raise ValueError("Must provide key_token (returned by the redact tool)")

    resolved = _resolve_key_token(key_token)
    if resolved is None:
        raise ValueError(
            "Token not found or expired — the process restarted, the "
            f"{_TOKEN_TTL_SECONDS // 60}-minute idle TTL elapsed, or the token "
            f"was evicted by the {_TOKEN_STORE_MAX}-entry process-global LRU "
            "bound. Re-run redact to obtain a fresh key_token."
        )

    key_dict, anchor, redacted = resolved
    # strict=True makes guarded_restore raise RestoreGuardError instead of
    # returning — before any original is substituted. Not caught here: an
    # uncaught exception is how the other tools in this module (see the
    # ValueError raises above) already surface a hard failure to the MCP
    # protocol caller, so a suspected injection or a failed guard is not
    # swallowed into a normal-looking JSON payload.
    # detailed=True for the structured `security_events` field in the JSON payload
    # below; warn=True because this tool wants the human-facing warning TOO, and
    # detailed=True would otherwise suppress it (guarded_restore's default is "warn
    # iff not detailed"). Surfacing stays guarded_restore's decision — one warning
    # over the merged (P/S + H) list, not a second one re-derived here.
    restored, details = guarded_restore(
        text,
        key_dict,
        redacted=redacted,
        anchor=anchor,
        guard=True,
        strict=strict,
        detailed=True,
        warn=True,
    )
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
    """Assess privacy risk of text. Returns redacted text, a full risk assessment
    (score, level, reasons, PIPL/GDPR/HIPAA fields), detection stats, a
    residual-risk flag, security events, a coverage advisory, and which detection
    layers ran. Deliberately withheld: entity spans (`entities[].original` is raw
    plaintext) and a restore key (this tool mints none).

    Args:
        text: Input text to assess for privacy risk.
        lang: Language code(s). Use comma-separated for multiple: "zh,en".
        mode: Detection mode — "fast" (regex), "ner" (regex+NER), "auto" (all).
    """
    lang_param: str | list[str] = lang
    if "," in lang:
        lang_param = [code.strip() for code in lang.split(",") if code.strip()]

    report: RedactReport = redact(
        text,
        lang=lang_param,
        mode=mode,
        report=True,
    )

    return json.dumps(
        {
            "risk": risk_payload(report.risk),
            # redact() always sets stats["total"] — contract pinned by test_mcp.py.
            # Kept alongside the full `stats` so the pinned key does not move.
            "entities_found": report.stats["total"],
            "stats": report.stats,
            "redacted": report.redacted_text,
            **common_report_fields(report),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool(name="info")
async def redact_info() -> str:
    """Show argus-redact version and installed capabilities."""
    import importlib
    import importlib.util

    from argus_redact.glue.redact import (
        _LANG_DISPLAY_NAMES,
        _LANG_PATTERNS,
        ner_engine_available,
    )
    from argus_redact.lang.shared.patterns import PATTERNS as SHARED

    lang_info = {}
    for code in _LANG_PATTERNS:
        mod_code = "in_" if code == "in" else code
        try:
            mod = importlib.import_module(f"argus_redact.lang.{mod_code}.patterns")
            count = len(mod.PATTERNS) + len(SHARED)
        except ModuleNotFoundError:
            count = 0
        has_ner = ner_engine_available(code)
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
