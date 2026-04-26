"""Streaming pseudonym-llm redaction and restoration.

Two complementary classes:
- ``StreamingRestorer`` — buffer streaming LLM output and restore at sentence boundaries.
- ``StreamingRedactor`` — chunked input redaction with cross-chunk key continuity
  (same original value across chunks maps to same realistic fake).

Both require caller to feed *complete logical units* (sentences, paragraphs, turns).
True byte-level streaming with realistic mode requires complete entity boundaries
and is roadmapped for a later release.
"""

from __future__ import annotations

from argus_redact._types import PseudonymLLMResult
from argus_redact.pure.restore import restore


class StreamingRestorer:
    """Buffer streaming LLM output and restore PII at boundaries.

    Strategies:
        "sentence" (default) — flush at sentence boundaries (。.！!？?；;\\n)
        "none" — restore every chunk immediately (no buffering)

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

    def __init__(self, key: dict, strategy: str = "sentence"):
        self._key = key
        self._buffer = ""
        if strategy not in ("sentence", "none"):
            raise ValueError(f"Unknown strategy '{strategy}'. Use 'sentence' or 'none'.")
        self._strategy = strategy

    def feed(self, chunk: str) -> str:
        """Feed a chunk. Returns restored text based on strategy."""
        if self._strategy == "none":
            return restore(chunk, self._key)

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


class StreamingRedactor:
    """Per-chunk realistic redaction with cross-chunk key continuity.

    Each ``.feed(chunk)`` runs the full pseudonym-llm pipeline on the chunk
    and returns a ``PseudonymLLMResult``. Same original value across chunks
    maps to the same fake (via shared salt + accumulated key dict).

    Caller MUST feed complete logical units (sentence / paragraph / turn).
    Entity boundaries that cross chunk boundaries are NOT handled — split
    such inputs at logical boundaries first.

    Usage:
        redactor = StreamingRedactor(salt=b"my-secret-salt", lang="zh")
        for chunk in input_stream:                  # one sentence/paragraph/turn each
            result = redactor.feed(chunk)
            send_to_llm(result.downstream_text)
        # Aggregate key for cross-chunk restore
        full_key = redactor.aggregate_key()
    """

    def __init__(
        self,
        *,
        salt: bytes,
        display_marker: str | None = None,
        lang: str | list[str] = "zh",
        mode: str = "fast",
        names: list[str] | None = None,
        types: list[str] | None = None,
        types_exclude: list[str] | None = None,
        strict_input: bool = True,
    ):
        if not isinstance(salt, (bytes, bytearray)):
            raise TypeError(f"salt must be bytes, got {type(salt).__name__}")
        self._salt = bytes(salt)
        self._display_marker = display_marker
        self._lang = lang
        self._mode = mode
        self._names = names
        self._types = types
        self._types_exclude = types_exclude
        self._strict_input = strict_input
        self._accumulated_key: dict[str, str] = {}

    def feed(self, chunk: str) -> PseudonymLLMResult:
        """Redact a single complete logical unit. Cross-chunk consistency preserved.

        Returns a ``PseudonymLLMResult`` for this chunk; the chunk-local ``key``
        contains only entries used in this chunk, but each entry is consistent
        with prior chunks (same original → same fake).
        """
        from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm

        result = redact_pseudonym_llm(
            chunk,
            salt=self._salt,
            display_marker=self._display_marker,
            lang=self._lang,
            mode=self._mode,
            names=self._names,
            types=self._types,
            types_exclude=self._types_exclude,
            strict_input=self._strict_input,
            existing_key=self._accumulated_key,
        )
        # Merge new entries into the accumulated key. Existing entries already
        # consistent (replace() honored existing_key); collisions can't happen
        # because realistic and audit pseudonym spaces are disjoint by construction.
        for fake, original in result.key.items():
            self._accumulated_key.setdefault(fake, original)
        return result

    def aggregate_key(self) -> dict[str, str]:
        """Return a copy of the unified key across all fed chunks."""
        return dict(self._accumulated_key)
