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

from argus_redact import redact
from argus_redact.integrations._session import _RedactSession, _RestoreSession


class RedactRunnable(_RedactSession):
    """Redact PII from text. Single-session: one instance per logical conversation.

    Compatible with LangChain's Runnable protocol (invoke method).
    """

    def invoke(self, text: str) -> str:
        return self._redact_once(text, redact_fn=redact)

    async def ainvoke(self, text: str) -> str:
        """Async version of invoke for LangChain async chains."""
        return self.invoke(text)


class RestoreRunnable(_RestoreSession):
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

    Pass aliases={fake: (alternate, ...)} (and optionally display_marker=) to
    map cross-language alias forms the LLM emitted back to the original — the
    session-level analogue of restore(text, key, aliases=...).
    """

    def __init__(
        self,
        redact_runnable: RedactRunnable,
        *,
        strict: bool = False,
        aliases: dict[str, tuple[str, ...]] | None = None,
        display_marker: str | None = None,
    ):
        super().__init__(
            redact_runnable,
            strict=strict,
            aliases=aliases,
            display_marker=display_marker,
        )

    def invoke(self, text: str) -> str:
        return self._restore_once(
            text,
            missing_key_msg=(
                "RestoreRunnable.invoke() called before paired RedactRunnable "
                "produced a key. Call redact_r.invoke(...) first, or check that "
                ".reset() was not called between them."
            ),
        )

    async def ainvoke(self, text: str) -> str:
        """Async version of invoke for LangChain async chains."""
        return self.invoke(text)
