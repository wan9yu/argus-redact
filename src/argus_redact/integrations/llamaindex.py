"""LlamaIndex integration — RedactTransform and RestoreTransform.

Callable objects that fit into LlamaIndex QueryPipeline or any
callable-based pipeline. No LlamaIndex dependency required.

Usage:
    redact_t = RedactTransform(mode="fast", lang="zh")
    restore_t = RestoreTransform(redact_t)

    redacted = redact_t(user_query)
    llm_output = llm(redacted)
    restored = restore_t(llm_output)
"""

from __future__ import annotations

from argus_redact import redact, restore


class RedactTransform:
    """Callable that redacts PII. Tracks key for later restoration."""

    def __init__(
        self,
        *,
        mode: str = "fast",
        lang: str | list[str] = "zh",
        seed: int | None = None,
    ):
        self._mode = mode
        self._lang = lang
        self._seed = seed
        self.last_key: dict | None = None

    def __call__(self, text: str, **kwargs) -> str:
        redacted, self.last_key = redact(
            text,
            mode=self._mode,
            lang=self._lang,
            seed=self._seed,
            key=self.last_key,
        )
        return redacted

    def reset(self):
        self.last_key = None


class RestoreTransform:
    """Callable that restores redacted text using key from RedactTransform."""

    def __init__(self, redact_transform: RedactTransform):
        self._redact = redact_transform

    def __call__(self, text: str, **kwargs) -> str:
        if self._redact.last_key is None:
            return text
        return restore(text, self._redact.last_key)
