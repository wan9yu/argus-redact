"""Private incremental-detection buffer for v0.5.7+ streaming.

``_StreamingBuffer`` is a stateful wrapper around ``_detect_partial``. The
public surface (``StreamingRedactor``) drives this class internally; direct
usage is private.
"""

from __future__ import annotations

from argus_redact._types import PatternMatch
from argus_redact.glue._detect_partial import _detect_partial


class _StreamingBuffer:
    """Accumulate text chunks; emit entities at sentence boundaries.

    Usage::

        buf = _StreamingBuffer(lang="zh", mode="fast")
        for chunk in stream:
            for entity in buf.feed(chunk):
                ...  # process complete entity
        for entity in buf.flush():
            ...  # final flush at end-of-stream
    """

    def __init__(
        self,
        *,
        lang: str | list[str] = "zh",
        mode: str = "fast",
        names: list[str] | None = None,
        types: list[str] | None = None,
        types_exclude: list[str] | None = None,
        max_buffer: int = 4096,
    ):
        self._lang = lang
        self._mode = mode
        self._names = names
        self._types = types
        self._types_exclude = types_exclude
        self._max_buffer = max_buffer
        self._buffer: str = ""

    def feed(self, chunk: str) -> list[PatternMatch]:
        """Add ``chunk`` to the buffer; return entities now complete."""
        entities, residual = _detect_partial(
            chunk,
            prev_buffer=self._buffer,
            lang=self._lang,
            mode=self._mode,
            names=self._names,
            types=self._types,
            types_exclude=self._types_exclude,
            max_buffer=self._max_buffer,
        )
        self._buffer = residual
        return entities

    def flush(self) -> list[PatternMatch]:
        """End-of-stream flush — detect anything still in the buffer."""
        if not self._buffer:
            return []
        entities, _ = _detect_partial(
            "",
            prev_buffer=self._buffer,
            lang=self._lang,
            mode=self._mode,
            names=self._names,
            types=self._types,
            types_exclude=self._types_exclude,
            max_buffer=self._max_buffer,
            force_flush=True,
        )
        self._buffer = ""
        return entities
