"""LangChain integration — RedactRunnable and RestoreRunnable.

Both classes are **single-session**: construct one pair per logical conversation,
not per process. If you need to reuse across distinct sessions, call .reset()
between them. Cross-session reuse without reset is a multi-tenant PII leak
vector — the same shared instance will restore one user's pseudonyms inside
another user's response.

Usage (single session):
    redact_r = RedactRunnable(mode="fast", lang="zh")
    restore_r = RestoreRunnable(redact_r)
    redacted = redact_r.invoke(user_input)
    # Inject the anchor prompt into your LLM system message:
    anchor_prompt = redact_r.make_prompt_addendum()
    llm_output = call_llm(redacted, system=anchor_prompt)
    restored = restore_r.invoke(llm_output)

Usage with LangChain (single session per chain instance):
    from langchain_core.runnables import RunnableLambda
    from langchain_openai import ChatOpenAI

    redact_r = RedactRunnable(mode="fast", lang="zh")
    restore_r = RestoreRunnable(redact_r)

    chain = (
        redact_r
        | ChatOpenAI(model="gpt-4o")
        | RunnableLambda(lambda msg: msg.content)
        | restore_r
    )
"""

from __future__ import annotations

import threading

from argus_redact import redact
from argus_redact.compose import make_anchor, prompt_anchor
from argus_redact.exceptions import SessionStateError
from argus_redact.glue.guarded_restore import guarded_restore


class RedactRunnable:
    """Redact PII from text. Single-session: one instance per logical conversation.

    Compatible with LangChain's Runnable protocol (invoke method).
    """

    def __init__(
        self,
        *,
        mode: str = "fast",
        lang: str | list[str] = "zh",
        salt: int | bytes | None = None,
    ):
        self._mode = mode
        self._lang = lang
        self._salt = salt
        self._lock = threading.Lock()
        self.last_key: dict | None = None
        self.last_anchor = None
        self._last_redacted: str | None = None

    def invoke(self, text: str) -> str:
        with self._lock:
            redacted, self.last_key = redact(
                text,
                mode=self._mode,
                lang=self._lang,
                salt=self._salt,
                key=self.last_key,
            )
            self.last_anchor = make_anchor(self.last_key)
            self._last_redacted = redacted
        return redacted

    async def ainvoke(self, text: str) -> str:
        """Async version of invoke for LangChain async chains."""
        return self.invoke(text)

    def make_prompt_addendum(self, lang: str | None = None) -> str:
        """Return a system-prompt addendum embedding the nonce-echo instruction.

        Callers must inject this into the LLM system message so the nonce
        reaches the response and the anchor round-trip can be verified.
        Returns an empty string if no redaction has occurred yet.
        """
        with self._lock:
            key = self.last_key
            anchor = self.last_anchor
        if not key or anchor is None:
            return ""
        effective_lang = (
            lang if lang is not None else (self._lang if isinstance(self._lang, str) else "zh")
        )
        return prompt_anchor(key, effective_lang, anchor=anchor)

    def reset(self) -> None:
        """Clear the accumulated key. Call between distinct logical sessions."""
        with self._lock:
            self.last_key = None
            self.last_anchor = None
            self._last_redacted = None


class RestoreRunnable:
    """Restore PII in text using the key from a paired RedactRunnable.

    Compatible with LangChain's Runnable protocol (invoke method).

    Raises SessionStateError if the paired RedactRunnable has not produced
    a key yet (or has been .reset()).

    Guard note: restore() runs with guard=True internally. If
    make_prompt_addendum() was not injected into the LLM system message,
    the nonce will be absent from the response and restore fail-closes —
    returning pseudonyms unchanged and emitting a UserWarning, not raising.
    Wire make_prompt_addendum() into the system prompt to enable guarded restore.
    Pass strict=True to the constructor to raise RestoreGuardError instead of
    warning on either the deterministic guard or a suspected injection.
    """

    def __init__(self, redact_runnable: RedactRunnable, *, strict: bool = False):
        self._redact = redact_runnable
        self._strict = strict

    def invoke(self, text: str) -> str:
        key = self._redact.last_key
        if key is None:
            raise SessionStateError(
                "RestoreRunnable.invoke() called before paired RedactRunnable "
                "produced a key. Call redact_r.invoke(...) first, or check that "
                ".reset() was not called between them."
            )

        return guarded_restore(
            text,
            key,
            redacted=self._redact._last_redacted,
            anchor=self._redact.last_anchor,
            guard=True,
            strict=self._strict,
        )

    async def ainvoke(self, text: str) -> str:
        """Async version of invoke for LangChain async chains."""
        return self.invoke(text)
