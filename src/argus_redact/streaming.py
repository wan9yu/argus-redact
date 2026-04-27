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
from argus_redact.glue._detect_partial import _consume_to_boundary
from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm
from argus_redact.pure.restore import restore


def _empty_result() -> PseudonymLLMResult:
    # Fresh instance per call: ``key`` is a mutable dict — sharing a singleton
    # would let one caller's mutation leak into another caller's "empty" result.
    return PseudonymLLMResult(audit_text="", downstream_text="", display_text="", key={})

# Integer schema version stamped into export_state() output. Decoupled from
# the package version on purpose — bumped only when the state shape itself
# changes, so most package releases leave it untouched.
_STATE_SCHEMA_VERSION = 1


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

    Key retention: ``_accumulated_key`` grows monotonically over the session.
    Construct one ``StreamingRedactor`` per logical session and discard it when
    the session ends; long-running services that share one redactor across
    unrelated conversations will accumulate unbounded entries.

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
        reserved_names: dict[str, tuple[str, ...]] | None = None,
        incremental: bool = False,
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
        self._reserved_names = reserved_names
        self._incremental = incremental
        self._inc_buffer: str = ""
        self._accumulated_key: dict[str, str] = {}

    def feed(self, chunk: str) -> PseudonymLLMResult:
        """Redact a chunk. Cross-chunk consistency preserved via shared key.

        Default mode (``incremental=False``): caller MUST feed complete logical
        units; entities split across chunk boundaries are NOT detected.

        Incremental mode (``incremental=True``, v0.5.7+): chunks accumulate
        until a sentence boundary, then the buffered prefix is redacted. Returns
        an empty ``PseudonymLLMResult`` when the buffer has no boundary yet.
        Call ``flush()`` at end-of-stream to drain a tail with no boundary.
        """
        if self._incremental:
            return self._feed_incremental(chunk)
        return self._redact_and_merge(chunk)

    def flush(self) -> PseudonymLLMResult:
        """End-of-stream flush — only meaningful in incremental mode.

        Drains any text accumulated past the last sentence boundary,
        running the full redact pipeline on it. Returns an empty
        ``PseudonymLLMResult`` if the buffer is empty.
        """
        if not self._incremental or not self._inc_buffer:
            return _empty_result()
        emit = self._inc_buffer
        self._inc_buffer = ""
        return self._redact_and_merge(emit)

    def _feed_incremental(self, chunk: str) -> PseudonymLLMResult:
        emit_text, residual = _consume_to_boundary(self._inc_buffer, chunk)
        self._inc_buffer = residual
        if not emit_text:
            return _empty_result()
        return self._redact_and_merge(emit_text)

    def _redact_and_merge(self, text: str) -> PseudonymLLMResult:
        result = redact_pseudonym_llm(
            text,
            salt=self._salt,
            display_marker=self._display_marker,
            lang=self._lang,
            mode=self._mode,
            names=self._names,
            types=self._types,
            types_exclude=self._types_exclude,
            strict_input=self._strict_input,
            reserved_names=self._reserved_names,
            existing_key=self._accumulated_key,
        )
        # setdefault preserves first-seen mapping; realistic and audit spaces
        # are disjoint by construction, so collisions are impossible.
        for fake, original in result.key.items():
            self._accumulated_key.setdefault(fake, original)
        return result

    def aggregate_key(self) -> dict[str, str]:
        """Return a copy of the unified key across all fed chunks."""
        return dict(self._accumulated_key)

    def export_state(self) -> dict:
        """Serialize this redactor's state to a JSON-friendly dict.

        Round-tripping the result through JSON and back into ``from_state``
        produces an instance whose subsequent ``feed()`` calls reuse the same
        fake values for already-seen originals — supports cross-process
        resume of a long-running session.

        ``salt`` is hex-encoded; everything else is plain str / list / dict.
        """
        return {
            "version": _STATE_SCHEMA_VERSION,
            "salt": self._salt.hex(),
            "accumulated_key": dict(self._accumulated_key),
            "lang": self._lang,
            "mode": self._mode,
            "display_marker": self._display_marker,
            "names": list(self._names) if self._names is not None else None,
            "types": list(self._types) if self._types is not None else None,
            "types_exclude": (
                list(self._types_exclude) if self._types_exclude is not None else None
            ),
            "strict_input": self._strict_input,
            "reserved_names": (
                {k: list(v) for k, v in self._reserved_names.items()}
                if self._reserved_names is not None
                else None
            ),
        }

    @classmethod
    def from_state(cls, state: dict) -> "StreamingRedactor":
        """Rebuild a StreamingRedactor from a previously exported state dict.

        Pure replay — no kwargs override. Modify ``state`` yourself before
        passing if you need to change configuration.
        """
        version = state.get("version")
        if version != _STATE_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported state schema version {version!r}; this release "
                f"reads schema {_STATE_SCHEMA_VERSION} only."
            )
        reserved = state.get("reserved_names")
        instance = cls(
            salt=bytes.fromhex(state["salt"]),
            display_marker=state.get("display_marker"),
            lang=state.get("lang", "zh"),
            mode=state.get("mode", "fast"),
            names=state.get("names"),
            types=state.get("types"),
            types_exclude=state.get("types_exclude"),
            strict_input=state.get("strict_input", True),
            reserved_names=(
                {k: tuple(v) for k, v in reserved.items()}
                if reserved is not None
                else None
            ),
        )
        instance._accumulated_key = dict(state.get("accumulated_key", {}))
        return instance
