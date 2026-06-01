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
    llm_output = call_llm(redacted)
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

from argus_redact import redact, restore
from argus_redact.exceptions import SessionStateError


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

    def invoke(self, text: str) -> str:
        with self._lock:
            redacted, self.last_key = redact(
                text,
                mode=self._mode,
                lang=self._lang,
                salt=self._salt,
                key=self.last_key,
            )
        return redacted

    async def ainvoke(self, text: str) -> str:
        """Async version of invoke for LangChain async chains."""
        return self.invoke(text)

    def reset(self) -> None:
        """Clear the accumulated key. Call between distinct logical sessions."""
        with self._lock:
            self.last_key = None


class RestoreRunnable:
    """Restore PII in text using the key from a paired RedactRunnable.

    Compatible with LangChain's Runnable protocol (invoke method).

    Raises SessionStateError if the paired RedactRunnable has not produced
    a key yet (or has been .reset()).
    """

    def __init__(self, redact_runnable: RedactRunnable):
        self._redact = redact_runnable

    def invoke(self, text: str) -> str:
        key = self._redact.last_key
        if key is None:
            raise SessionStateError(
                "RestoreRunnable.invoke() called before paired RedactRunnable "
                "produced a key. Call redact_r.invoke(...) first, or check that "
                ".reset() was not called between them."
            )
        return restore(text, key)

    async def ainvoke(self, text: str) -> str:
        """Async version of invoke for LangChain async chains."""
        return self.invoke(text)
