"""LangChain integration — RedactRunnable and RestoreRunnable.

Usage without LangChain (standalone):
    redact_r = RedactRunnable(mode="fast", lang="zh")
    restore_r = RestoreRunnable(redact_r)

    redacted = redact_r.invoke(user_input)
    llm_output = call_llm(redacted)
    restored = restore_r.invoke(llm_output)

Usage with LangChain:
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

import contextvars
import threading

from argus_redact import redact, restore

_current_key: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "argus_redact_key", default=None
)


class RedactRunnable:
    """Redact PII from text. Thread-safe key tracking via contextvars.

    Compatible with LangChain's Runnable protocol (invoke method).
    """

    def __init__(
        self,
        *,
        mode: str = "auto",
        lang: str | list[str] = "zh",
        seed: int | None = None,
    ):
        self._mode = mode
        self._lang = lang
        self._seed = seed
        self._lock = threading.Lock()
        self.last_key: dict | None = None

    def invoke(self, text: str) -> str:
        with self._lock:
            redacted, self.last_key = redact(
                text,
                mode=self._mode,
                lang=self._lang,
                seed=self._seed,
                key=self.last_key,
            )
            _current_key.set(self.last_key)
        return redacted

    async def ainvoke(self, text: str) -> str:
        """Async version of invoke for LangChain async chains."""
        return self.invoke(text)

    def reset(self):
        """Clear the key for a new session."""
        with self._lock:
            self.last_key = None
            _current_key.set(None)


class RestoreRunnable:
    """Restore PII in text using the key from a paired RedactRunnable.

    Compatible with LangChain's Runnable protocol (invoke method).
    """

    def __init__(self, redact_runnable: RedactRunnable):
        self._redact = redact_runnable

    def invoke(self, text: str) -> str:
        key = self._redact.last_key
        if key is None:
            return text
        return restore(text, key)

    async def ainvoke(self, text: str) -> str:
        """Async version of invoke for LangChain async chains."""
        return self.invoke(text)
