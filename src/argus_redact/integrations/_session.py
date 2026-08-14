"""Shared single-session base classes for the LangChain and LlamaIndex adapters.

`integrations/langchain.py` and `integrations/llamaindex.py` expose near-identical
redact/restore session pairs; the run-method names, the ctor param names, and two
user-visible strings are the only real differences. The shared state, the locked
redact body, the prompt addendum, the reset, and the guarded-restore body live here
so the two public adapters stay byte-for-byte in agreement on everything that is not
framework-specific.

These classes are private (leading underscore); the public surface is the
RedactRunnable/RestoreRunnable and RedactTransform/RestoreTransform subclasses.
"""

from __future__ import annotations

import threading

from argus_redact.compose import make_anchor, prompt_anchor
from argus_redact.exceptions import SessionStateError
from argus_redact.glue.guarded_restore import guarded_restore
from argus_redact.glue.redact import _effective_lang


class _RedactSession:
    """Single-session redact state shared by the framework adapters.

    Holds the accumulating key/anchor and the locked redact body. Subclasses add
    only the framework-specific run method (invoke / __call__).
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

    def _redact_once(self, text: str, *, redact_fn) -> str:
        # redact_fn is resolved by the subclass from ITS module namespace at call
        # time (not imported here) so a test patching e.g. `llamaindex.redact`
        # still intercepts the call that happens inside this locked section — the
        # lock must wrap the redact() call itself, not just the attribute writes.
        with self._lock:
            redacted, self.last_key = redact_fn(
                text,
                mode=self._mode,
                lang=self._lang,
                salt=self._salt,
                key=self.last_key,
            )
            self.last_anchor = make_anchor(self.last_key)
            self._last_redacted = redacted
        return redacted

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
        effective_lang = lang if lang is not None else _effective_lang(self._lang)
        return prompt_anchor(key, effective_lang, anchor=anchor)

    def reset(self) -> None:
        """Clear the accumulated key. Call between distinct logical sessions."""
        with self._lock:
            self.last_key = None
            self.last_anchor = None
            self._last_redacted = None


class _RestoreSession:
    """Single-session restore state shared by the framework adapters.

    Holds the paired redact session plus the restore options and the shared
    guarded-restore body. Subclasses add the framework-specific run method and
    supply the framework-specific "no key yet" message via `_restore_once`.
    """

    def __init__(
        self,
        redact_session: _RedactSession,
        *,
        strict: bool = False,
        aliases: dict[str, tuple[str, ...]] | None = None,
        display_marker: str | None = None,
    ):
        self._redact = redact_session
        self._strict = strict
        self._aliases = aliases
        self._display_marker = display_marker

    def _restore_once(self, text: str, *, missing_key_msg: str) -> str:
        key = self._redact.last_key
        if key is None:
            raise SessionStateError(missing_key_msg)

        return guarded_restore(
            text,
            key,
            redacted=self._redact._last_redacted,
            anchor=self._redact.last_anchor,
            guard=True,
            strict=self._strict,
            aliases=self._aliases,
            display_marker=self._display_marker,
        )
