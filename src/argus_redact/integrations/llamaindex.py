"""LlamaIndex integration — RedactTransform and RestoreTransform.

Callable objects that fit into LlamaIndex QueryPipeline or any
callable-based pipeline. No LlamaIndex dependency required.

Both classes are **single-session**: construct one pair per logical conversation,
not per process. If you need to reuse across distinct sessions, call .reset()
between them. Cross-session reuse without reset is a multi-tenant PII leak
vector — the same shared instance will substitute one user's pseudonyms inside
another user's text.

Usage:
    redact_t = RedactTransform(mode="fast", lang="zh")
    restore_t = RestoreTransform(redact_t)

    redacted = redact_t(user_query)
    llm_output = llm(redacted)
    restored = restore_t(llm_output)
"""

from __future__ import annotations

from argus_redact import redact, restore
from argus_redact.exceptions import SessionStateError


class RedactTransform:
    """Callable that redacts PII. Single-session: one instance per logical conversation."""

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
        self.last_key: dict | None = None

    def __call__(self, text: str, **kwargs) -> str:
        redacted, self.last_key = redact(
            text,
            mode=self._mode,
            lang=self._lang,
            salt=self._salt,
            key=self.last_key,
        )
        return redacted

    def reset(self) -> None:
        """Clear the accumulated key between distinct logical sessions."""
        self.last_key = None


class RestoreTransform:
    """Callable that restores redacted text using key from RedactTransform.

    Raises SessionStateError if the paired RedactTransform has not produced
    a key yet (or has been .reset()).
    """

    def __init__(self, redact_transform: RedactTransform):
        self._redact = redact_transform

    def __call__(self, text: str, **kwargs) -> str:
        key = self._redact.last_key
        if key is None:
            raise SessionStateError(
                "RestoreTransform called before paired RedactTransform produced "
                "a key. Call redact_t(...) first, or check .reset() was not "
                "called between them."
            )
        return restore(text, key)
