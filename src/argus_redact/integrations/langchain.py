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

from argus_redact import redact, restore


class RedactRunnable:
    """Redact PII from text. Tracks key for later restoration.

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
        self.last_key: dict | None = None

    def invoke(self, text: str) -> str:
        redacted, self.last_key = redact(
            text,
            mode=self._mode,
            lang=self._lang,
            seed=self._seed,
            key=self.last_key,
        )
        return redacted

    def reset(self):
        """Clear the key for a new session."""
        self.last_key = None


class RestoreRunnable:
    """Restore PII in text using the key from a paired RedactRunnable.

    Compatible with LangChain's Runnable protocol (invoke method).
    """

    def __init__(self, redact_runnable: RedactRunnable):
        self._redact = redact_runnable

    def invoke(self, text: str) -> str:
        if self._redact.last_key is None:
            return text
        return restore(text, self._redact.last_key)
