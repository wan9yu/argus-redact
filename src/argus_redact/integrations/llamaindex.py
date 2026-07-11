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
    # Inject the anchor prompt into your LLM system message:
    anchor_prompt = redact_t.make_prompt_addendum()
    llm_output = llm(redacted, system=anchor_prompt)
    restored = restore_t(llm_output)
"""

from __future__ import annotations

import warnings as _warnings

from argus_redact import redact, restore
from argus_redact.compose import make_anchor, prompt_anchor
from argus_redact.exceptions import SessionStateError
from argus_redact.pure.restore import check_restore_safety
from argus_redact.pure.security_events import INJECTION_SUSPECTED, security_event


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
        self.last_anchor = None
        self._last_redacted: str | None = None

    def __call__(self, text: str, **kwargs) -> str:
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

    def make_prompt_addendum(self, lang: str | None = None) -> str:
        """Return a system-prompt addendum embedding the nonce-echo instruction.

        Callers must inject this into the LLM system message so the nonce
        reaches the response and the anchor round-trip can be verified.
        Returns an empty string if no redaction has occurred yet.
        """
        key = self.last_key
        anchor = self.last_anchor
        if not key or anchor is None:
            return ""
        effective_lang = (
            lang if lang is not None else (self._lang if isinstance(self._lang, str) else "zh")
        )
        return prompt_anchor(key, effective_lang, anchor=anchor)

    def reset(self) -> None:
        """Clear the accumulated key between distinct logical sessions."""
        self.last_key = None
        self.last_anchor = None
        self._last_redacted = None


class RestoreTransform:
    """Callable that restores redacted text using key from RedactTransform.

    Raises SessionStateError if the paired RedactTransform has not produced
    a key yet (or has been .reset()).

    Guard note: restore() runs with guard=True internally. If
    make_prompt_addendum() was not injected into the LLM system message,
    the nonce will be absent from the response and restore fail-closes —
    returning pseudonyms unchanged and emitting a UserWarning, not raising.
    Wire make_prompt_addendum() into the system prompt to enable guarded restore.
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
        anchor = self._redact.last_anchor
        redacted = self._redact._last_redacted

        # (H) supplementary heuristic check — runs when we have the redacted prompt
        security_events: list[dict] = []
        if redacted is not None:
            hints = check_restore_safety(redacted, text, key)
            if hints:
                security_events.append(
                    security_event(
                        INJECTION_SUSPECTED,
                        count=len(hints),
                        detail="; ".join(hints),
                    )
                )

        result, details = restore(text, key, guard=True, anchor=anchor, detailed=True)
        all_events = security_events + details.get("security_events", [])
        if all_events:
            _warnings.warn(
                f"restore security events: {[e['reason_code'] for e in all_events]}",
                stacklevel=2,
            )
        return result
