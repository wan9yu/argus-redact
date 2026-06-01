"""Session isolation tests for LangChain / LlamaIndex integration adapters.

These adapters are single-session by contract (one instance per logical
conversation). RestoreRunnable / RestoreTransform raise SessionStateError
when their paired Redact helper has not yet produced a key, or has been
.reset(). This catches the audit HIGH finding about silent cross-session
PII bridging when the helper is reused across users without reset.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from argus_redact import SessionStateError
from argus_redact.integrations.langchain import RedactRunnable, RestoreRunnable
from argus_redact.integrations.llamaindex import RedactTransform, RestoreTransform

# ---------- LangChain ----------

def test_langchain_happy_path_roundtrip():
    """Single session: redact → restore returns original verbatim."""
    redact_r = RedactRunnable(mode="fast", lang="zh", salt=42)
    restore_r = RestoreRunnable(redact_r)
    redacted = redact_r.invoke("张三的电话13812345678")
    # Sanity: PII is masked
    assert "13812345678" not in redacted
    assert "张三" not in redacted
    # Round-trip recovers the source
    restored = restore_r.invoke(redacted)
    assert restored == "张三的电话13812345678"


def test_langchain_multi_invoke_accumulates_within_session():
    """Within ONE logical session, repeated invoke() accumulates the key.
    This is documented behavior, not a bug — keys merge for round-trip.
    """
    redact_r = RedactRunnable(mode="fast", lang="zh", salt=42)
    redact_r.invoke("黄芳的电话13912345678")
    redact_r.invoke("王建国的身份证110101199003074610")
    assert redact_r.last_key is not None
    originals = set(redact_r.last_key.values())
    assert "13912345678" in originals
    assert "110101199003074610" in originals


def test_langchain_restore_without_key_raises():
    """RestoreRunnable raises SessionStateError if redact never ran."""
    redact_r = RedactRunnable(mode="fast", lang="zh", salt=42)
    restore_r = RestoreRunnable(redact_r)
    with pytest.raises(SessionStateError, match="before paired RedactRunnable"):
        restore_r.invoke("some redacted text")


def test_langchain_restore_after_reset_raises():
    """After .reset(), subsequent restore must raise (state was deliberately cleared)."""
    redact_r = RedactRunnable(mode="fast", lang="zh", salt=42)
    restore_r = RestoreRunnable(redact_r)
    redact_r.invoke("张三的电话13812345678")
    redact_r.reset()
    with pytest.raises(SessionStateError):
        restore_r.invoke("anything")


def test_langchain_docstring_states_single_session():
    """Class-level docstring must mention single-session semantics."""
    doc = (RedactRunnable.__doc__ or "") + " " + (RestoreRunnable.__doc__ or "")
    # Module-level docstring also counts
    import argus_redact.integrations.langchain as mod
    doc += " " + (mod.__doc__ or "")
    assert re.search(r"single[- ]?session", doc, re.IGNORECASE), (
        "LangChain integration docstrings must explicitly mark single-session "
        "semantics to discourage cross-session sharing of one instance."
    )


def test_langchain_no_dead_contextvar_code():
    """The misleading _current_key ContextVar must be fully removed.

    Audit found the contextvar was set() but never get(); claim of
    'thread-safe via contextvars' was misleading. v0.6.6 strips it.
    """
    src = Path("src/argus_redact/integrations/langchain.py").read_text(encoding="utf-8")
    assert "contextvars" not in src, "contextvars import lingers"
    assert "_current_key" not in src, "dead _current_key ContextVar lingers"
    assert "contextvar" not in src.lower() or "single-session" in src.lower(), (
        "docstring still references contextvars without single-session context"
    )


# ---------- LlamaIndex ----------

def test_llamaindex_happy_path_roundtrip():
    redact_t = RedactTransform(mode="fast", lang="zh", salt=42)
    restore_t = RestoreTransform(redact_t)
    redacted = redact_t("张三的电话13812345678")
    assert "13812345678" not in redacted
    assert "张三" not in redacted
    assert restore_t(redacted) == "张三的电话13812345678"


def test_llamaindex_restore_without_key_raises():
    redact_t = RedactTransform(mode="fast", lang="zh", salt=42)
    restore_t = RestoreTransform(redact_t)
    with pytest.raises(SessionStateError, match="before paired RedactTransform"):
        restore_t("some redacted text")


def test_llamaindex_restore_after_reset_raises():
    redact_t = RedactTransform(mode="fast", lang="zh", salt=42)
    restore_t = RestoreTransform(redact_t)
    redact_t("张三的电话13812345678")
    redact_t.reset()
    with pytest.raises(SessionStateError):
        restore_t("anything")


def test_llamaindex_docstring_states_single_session():
    import argus_redact.integrations.llamaindex as mod
    doc = (
        (mod.__doc__ or "")
        + " "
        + (RedactTransform.__doc__ or "")
        + " "
        + (RestoreTransform.__doc__ or "")
    )
    assert re.search(r"single[- ]?session", doc, re.IGNORECASE)
