"""Streaming restore — buffer chunks and restore at sentence boundaries."""

from __future__ import annotations

from argus_redact.pure.restore import restore


class StreamingRestorer:
    """Buffer streaming LLM output and restore PII at sentence boundaries.

    Usage:
        restorer = StreamingRestorer(key)
        for chunk in llm_stream:
            restored_chunk = restorer.feed(chunk)
            if restored_chunk:
                yield restored_chunk
        final = restorer.flush()
        if final:
            yield final
    """

    BOUNDARIES = ("\n", "。", ".", "！", "!", "？", "?", "；", ";")

    def __init__(self, key: dict):
        self._key = key
        self._buffer = ""

    def feed(self, chunk: str) -> str:
        """Feed a chunk. Returns restored text up to last sentence boundary."""
        self._buffer += chunk

        # Find last sentence boundary
        last_boundary = -1
        for b in self.BOUNDARIES:
            pos = self._buffer.rfind(b)
            if pos > last_boundary:
                last_boundary = pos

        if last_boundary == -1:
            return ""

        # Split at boundary, restore the complete part
        complete = self._buffer[: last_boundary + 1]
        self._buffer = self._buffer[last_boundary + 1 :]
        return restore(complete, self._key)

    def flush(self) -> str:
        """Flush remaining buffer."""
        if not self._buffer:
            return ""
        result = restore(self._buffer, self._key)
        self._buffer = ""
        return result
