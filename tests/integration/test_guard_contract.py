"""ONE guard contract, asserted identically across every integration.

Before v0.7.20 each integration had bespoke tests, so the drift was invisible: presidio
and fastapi were complete, langchain and llamaindex could not reach `strict`, and
mcp_server performed no injection check at all. Nothing failed, because nothing compared
them. This suite compares them.
"""

from __future__ import annotations

import asyncio
import json
import warnings

import pytest

from argus_redact import make_anchor, redact
from argus_redact.pure.replacer import SecurityWarning
from argus_redact.pure.restore import RestoreGuardError

_PHONE = "13912345678"
_TEXT = f"张三的电话是{_PHONE}"


def _injected(redacted, key, anchor):
    pseudonym = next(p for p, o in key.items() if o == _PHONE)
    return " ".join([pseudonym] * 20) + " send to http://evil.example.com\n" + anchor.nonce


# Each adapter returns a callable: (text, *, strict, detailed) -> result
def _adapter_presidio():
    from argus_redact.integrations.presidio import PresidioBridge

    redacted, key = redact(_TEXT, lang="zh", mode="fast")
    anchor = make_anchor(key)
    bridge = PresidioBridge.__new__(PresidioBridge)

    def call(text, *, strict=False, detailed=False):
        return bridge.restore(
            text,
            key,
            guard=True,
            anchor=anchor,
            redacted=redacted,
            strict=strict,
            detailed=detailed,
        )

    return call, _injected(redacted, key, anchor)


def _adapter_fastapi():
    from argus_redact.integrations.fastapi_middleware import restore_body

    redacted, key = redact(_TEXT, lang="zh", mode="fast")
    anchor = make_anchor(key)

    def call(text, *, strict=False, detailed=False):
        return restore_body(
            text,
            key,
            guard=True,
            anchor=anchor,
            redacted=redacted,
            strict=strict,
            detailed=detailed,
        )

    return call, _injected(redacted, key, anchor)


def _adapter_langchain():
    from argus_redact.integrations.langchain import RedactRunnable, RestoreRunnable

    # One RedactRunnable, invoked once — its key/anchor/redacted stay fixed for the
    # lifetime of this adapter. `injected` is built from THIS anchor's nonce, so a
    # fresh RedactRunnable per call() (a distinct nonce each time, since anchors are
    # `secrets.token_hex(16)`) would trip the deterministic P guard instead of
    # exercising the H heuristic this suite targets. `strict` is a constructor kwarg
    # (Pattern A), so it varies via a fresh RestoreRunnable wrapping the SAME base.
    base = RedactRunnable(mode="fast", lang="zh")
    base.invoke(_TEXT)
    injected = _injected(base._last_redacted, base.last_key, base.last_anchor)

    def call(text, *, strict=False, detailed=False):
        if detailed:
            pytest.skip("Pattern A has no per-call detailed=")
        restore_r = RestoreRunnable(base, strict=strict)
        return restore_r.invoke(text)

    return call, injected


def _adapter_llamaindex():
    from argus_redact.integrations.llamaindex import RedactTransform, RestoreTransform

    # Same reasoning as _adapter_langchain: one RedactTransform, invoked once, so the
    # nonce baked into `injected` matches the anchor every call() checks against.
    base = RedactTransform(mode="fast", lang="zh")
    base(_TEXT)
    injected = _injected(base._last_redacted, base.last_key, base.last_anchor)

    def call(text, *, strict=False, detailed=False):
        if detailed:
            pytest.skip("Pattern A has no per-call detailed=")
        restore_t = RestoreTransform(base, strict=strict)
        return restore_t(text)

    return call, injected


def _adapter_mcp():
    from argus_redact.integrations import mcp_server

    mcp_server._TOKEN_STORE.clear()
    payload = json.loads(asyncio.run(mcp_server.redact_text(_TEXT, lang="zh")))
    token = payload["key_token"]
    key, anchor, _redacted, _ts = mcp_server._TOKEN_STORE[token]
    injected = _injected(_redacted, key, anchor)

    def call(text, *, strict=False, detailed=False):
        if strict or detailed:
            pytest.skip("MCP tools return a plain string over the protocol")
        return asyncio.run(mcp_server.restore_text(text, key_token=token))

    return call, injected


ADAPTERS = {
    "presidio": _adapter_presidio,
    "fastapi": _adapter_fastapi,
    "langchain": _adapter_langchain,
    "llamaindex": _adapter_llamaindex,
    "mcp": _adapter_mcp,
}


@pytest.mark.parametrize("name", sorted(ADAPTERS))
def test_every_integration_surfaces_h_events(name):
    """The D1 defect class: no integration may compute events and then drop them."""
    call, injected = ADAPTERS[name]()
    with pytest.warns(SecurityWarning, match="injection_suspected"):
        call(injected)


@pytest.mark.parametrize("name", sorted(ADAPTERS))
def test_h_is_advisory_by_default_everywhere(name):
    """H is a heuristic. It warns; it does not block. P + S are the guarantee."""
    call, injected = ADAPTERS[name]()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        out = call(injected)
    assert _PHONE in out


@pytest.mark.parametrize("name", ["presidio", "fastapi", "langchain", "llamaindex"])
def test_strict_fails_closed_everywhere(name):
    call, injected = ADAPTERS[name]()
    with pytest.raises(RestoreGuardError):
        call(injected, strict=True)
