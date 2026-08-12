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

from argus_redact import redact
from argus_redact.integrations._session import _RedactSession, _RestoreSession


class RedactTransform(_RedactSession):
    """Callable that redacts PII. Single-session: one instance per logical conversation."""

    def __call__(self, text: str, **kwargs) -> str:
        return self._redact_once(text, redact_fn=redact)


class RestoreTransform(_RestoreSession):
    """Callable that restores redacted text using key from RedactTransform.

    Raises SessionStateError if the paired RedactTransform has not produced
    a key yet (or has been .reset()).

    Guard note: restore() runs with guard=True internally. If
    make_prompt_addendum() was not injected into the LLM system message,
    the nonce will be absent from the response and restore fail-closes —
    returning pseudonyms unchanged and emitting a UserWarning, not raising.
    Wire make_prompt_addendum() into the system prompt to enable guarded restore.
    Pass strict=True to the constructor to raise RestoreGuardError instead of
    warning on either the deterministic guard or a suspected injection.

    Pass aliases={fake: (alternate, ...)} (and optionally display_marker=) to
    map cross-language alias forms the LLM emitted back to the original — the
    session-level analogue of restore(text, key, aliases=...).
    """

    def __init__(
        self,
        redact_transform: RedactTransform,
        *,
        strict: bool = False,
        aliases: dict[str, tuple[str, ...]] | None = None,
        display_marker: str | None = None,
    ):
        super().__init__(
            redact_transform,
            strict=strict,
            aliases=aliases,
            display_marker=display_marker,
        )

    def __call__(self, text: str, **kwargs) -> str:
        return self._restore_once(
            text,
            missing_key_msg=(
                "RestoreTransform called before paired RedactTransform produced "
                "a key. Call redact_t(...) first, or check .reset() was not "
                "called between them."
            ),
        )
