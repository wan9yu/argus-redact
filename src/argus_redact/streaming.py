"""Streaming pseudonym-llm redaction and restoration.

Two complementary classes:
- ``StreamingRestorer`` — buffer streaming LLM output and restore at sentence boundaries.
- ``StreamingRedactor`` — chunked input redaction with cross-chunk key continuity
  (same original value across chunks maps to same realistic fake). Detects ONCE over
  a buffer carrying ±W (``_EVIDENCE_CONTEXT_WINDOW``) of context and redacts the emit
  range with that detection — so streaming evidence-gated detection equals batch.
  Call ``flush()`` at end-of-stream to drain the held-back tail.

True byte-level streaming with realistic mode requires complete entity boundaries
and is roadmapped for a later release.
"""

from __future__ import annotations

import dataclasses
import warnings

from argus_redact._core_loader import _core
from argus_redact._types import PatternMatch, PseudonymLLMResult
from argus_redact.glue._detect_partial import (
    _EVIDENCE_CONTEXT_WINDOW,
    DEFAULT_MAX_BUFFER,
    _context_cut,
)
from argus_redact.glue.redact_pseudonym_llm import (
    _check_input_pollution,
    redact_pseudonym_llm,
)
from argus_redact.pure.restore import restore


def _empty_result() -> PseudonymLLMResult:
    # Fresh instance per call: backing storage is a mutable dict — sharing a
    # singleton would let one caller's mutation leak into another caller's
    # "empty" result.
    return PseudonymLLMResult(
        audit_text="", downstream_text="", display_text="", key={}, aliases={}
    )

# Integer schema version stamped into export_state() output. Decoupled from
# the package version on purpose — bumped only when the state shape itself
# changes, so most package releases leave it untouched.
_STATE_SCHEMA_VERSION = 1


def _resolve_state_salt(state: dict, salt: bytes | None) -> bytes:
    """Resolve the effective salt for ``StreamingRedactor.from_state``.

    Caller-supplied ``salt`` wins; legacy v0.6.0/v0.6.1 dumps with embedded
    ``state["salt"]`` still load (with DeprecationWarning); raise if neither.
    """
    if salt is not None:
        return salt
    embedded = state.get("salt")
    if embedded is None:
        raise ValueError(
            "from_state requires salt= kwarg (state does not contain an "
            "embedded salt). Pass the salt held out-of-band: "
            "StreamingRedactor.from_state(state, salt=<bytes>)."
        )
    warnings.warn(
        "Loading state with embedded salt is deprecated; pass salt= kwarg "
        "explicitly. Will be rejected in v0.7.0.",
        DeprecationWarning,
        stacklevel=3,
    )
    return bytes.fromhex(embedded)


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
        """Feed a chunk. Returns restored text based on strategy.

        The boundary split delegates to ``_core.streaming_restorer_split`` (the
        SSOT), which shares the redactor's ``_last_boundary_index`` rule: ``\\n``
        and the CJK ``。！？；`` always count; the ASCII ``.!?;`` count ONLY when
        the next buffer char is whitespace, and NEVER at the buffer end. A bare
        trailing ASCII ``.`` is ambiguous — it can be a realistic fake's internal
        dot (``user16068@example.net``, an IPv4 octet) sitting at the rightmost
        position of this ``feed``. Flushing on it would emit a half-token
        (``…@example.``) and restore the fragment, leaving the pseudonym
        unrestored; so the split holds the dot until the next chunk disambiguates.
        Returns ``(complete, residual)`` (``("", buffer)`` when no real boundary
        is present).
        """
        if self._strategy == "none":
            return restore(chunk, self._key)

        self._buffer += chunk

        complete, residual = _core.streaming_restorer_split(self._buffer)
        if not complete:
            return ""
        self._buffer = residual
        return restore(complete, self._key)

    def flush(self) -> str:
        """Flush remaining buffer."""
        if not self._buffer:
            return ""
        result = restore(self._buffer, self._key)
        self._buffer = ""
        return result


class StreamingRedactor:
    """Sentence-bounded incremental redaction with cross-chunk key continuity.

    Each ``.feed(chunk)`` accumulates input into a buffer that always carries
    ±W (``_EVIDENCE_CONTEXT_WINDOW`` = 128 chars) of context, then emits the
    range up to the last sentence boundary that still leaves ≥ W chars of
    forward context — redacted using a single full-buffer detection pass (not a
    re-detect of the bare slice). This makes streaming evidence-gated detection
    equal to batch: a candidate's ±W cue / proximate-PII window is always in
    scope. Call ``flush()`` at end-of-stream to drain the held-back tail with
    the same guarantee as batch's view of the end. Same original value across
    chunks maps to the same fake (via shared salt + accumulated key dict).

    Key retention: ``_accumulated_key`` grows monotonically over the session.
    Construct one ``StreamingRedactor`` per logical session and discard it when
    the session ends; long-running services that share one redactor across
    unrelated conversations will accumulate unbounded entries.

    Usage:
        redactor = StreamingRedactor(salt=b"my-secret-salt", lang="zh")
        for chunk in input_stream:
            result = redactor.feed(chunk)
            if result.downstream_text:
                send_to_llm(result.downstream_text)
        final = redactor.flush()
        if final.downstream_text:
            send_to_llm(final.downstream_text)
        # Aggregate key for cross-chunk restore
        full_key = redactor.aggregate_key()
    """

    def __init__(
        self,
        *,
        salt: int | bytes,
        display_marker: str | None = None,
        lang: str | list[str] = "zh",
        mode: str = "fast",
        names: list[str] | None = None,
        types: list[str] | None = None,
        types_exclude: list[str] | None = None,
        strict_input: bool = True,
        reserved_names: dict[str, tuple[str, ...]] | None = None,
    ):
        if not isinstance(salt, (int, bytes, bytearray)):
            raise TypeError(f"salt must be int or bytes, got {type(salt).__name__}")
        if isinstance(salt, int):
            signed = salt < 0
            self._salt = salt.to_bytes(8, "big", signed=signed)
        else:
            self._salt = bytes(salt)
        self._display_marker = display_marker
        self._lang = lang
        self._mode = mode
        self._names = names
        self._types = types
        self._types_exclude = types_exclude
        self._strict_input = strict_input
        self._reserved_names = reserved_names
        self._inc_buffer: str = ""
        # Length (CHARS) of the already-emitted left-context prefix retained at
        # the front of ``_inc_buffer`` for detection only (never re-emitted).
        # 0 initially; ``min(prev_cut, _EVIDENCE_CONTEXT_WINDOW)`` after each emit.
        self._ctx_len: int = 0
        self._accumulated_key: dict[str, str] = {}

    def feed(self, chunk: str) -> PseudonymLLMResult:
        """Accumulate ``chunk`` and emit up to the context-cut boundary, redacted.

        Returns an empty ``PseudonymLLMResult`` when the buffer hasn't reached a
        safe cut yet (less than ``_EVIDENCE_CONTEXT_WINDOW`` chars of forward
        context available). Call ``flush()`` at end-of-stream to drain the tail.
        Cross-chunk consistency is preserved via the shared accumulated key.
        """
        # Eager pollution check: run on the incoming chunk before buffering so
        # re-injected reserved-range values are caught even if the buffer hasn't
        # reached a cut yet (the check inside redact_pseudonym_llm only fires at
        # emit time, which may be deferred).
        if self._strict_input:
            _check_input_pollution(chunk, reserved_names=self._reserved_names)

        self._inc_buffer += chunk
        cut, redetect, entities = _context_cut(
            self._inc_buffer,
            self._ctx_len,
            lang=self._lang,
            mode=self._mode,
            names=self._names,
            types=self._types,
            types_exclude=self._types_exclude,
            max_buffer=DEFAULT_MAX_BUFFER,
            force_flush=False,
        )
        if cut <= self._ctx_len:
            return _empty_result()

        ctx = self._ctx_len  # snapshot before mutation
        emit = self._inc_buffer[ctx:cut]
        # On the forced bounded-drain split (``redetect``), the full-buffer
        # straddler would be dropped by ``_shift_entities`` and its head leaked
        # raw; re-detect the emit slice instead (``shifted=None`` →
        # ``redact_pseudonym_llm`` detects internally). A boundary-less
        # mega-buffer carries no cross-sentence evidence, so re-detecting the
        # bare slice is correct here (pre-rework drain safety).
        shifted = None if redetect else self._shift_entities(entities, ctx, cut)
        # Carry the last W chars (already emitted, for left-context) plus pending.
        lo = max(0, cut - _EVIDENCE_CONTEXT_WINDOW)
        self._inc_buffer = self._inc_buffer[lo:]
        self._ctx_len = cut - lo
        return self._redact_and_merge(emit, shifted)

    def flush(self) -> PseudonymLLMResult:
        """End-of-stream flush — drain pending buffer with no hold-back.

        Detects once on the full retained buffer (left-context ++ pending) with
        ``force_flush=True`` so the emit range sees end-of-stream context (≡
        batch's view of the tail). Returns an empty ``PseudonymLLMResult`` if
        the buffer is empty (no pending text beyond the left-context). Resets
        state.
        """
        if len(self._inc_buffer) <= self._ctx_len:
            self._inc_buffer = ""
            self._ctx_len = 0
            return _empty_result()
        cut, _redetect, entities = _context_cut(
            self._inc_buffer,
            self._ctx_len,
            lang=self._lang,
            mode=self._mode,
            names=self._names,
            types=self._types,
            types_exclude=self._types_exclude,
            max_buffer=DEFAULT_MAX_BUFFER,
            force_flush=True,
        )
        # force_flush never sets redetect (it drains to len with full-buffer
        # context ≡ batch's view of the tail), so always range-shift.
        ctx = self._ctx_len  # snapshot before reset
        emit = self._inc_buffer[ctx:cut]
        shifted = self._shift_entities(entities, ctx, cut)
        self._inc_buffer = ""
        self._ctx_len = 0
        return self._redact_and_merge(emit, shifted)

    @staticmethod
    def _shift_entities(
        entities: list[PatternMatch], lo: int, hi: int
    ) -> list[PatternMatch]:
        """Re-base the final entity set onto the emit slice ``[lo, hi)``.

        Exact mirror of the core SSOT ``shift_spans`` (see
        ``crates/argus-redact-core/src/streaming.rs``): keep every entity that
        ENDS within the range (``lo < end ≤ hi``) and subtract ``lo`` from its
        offsets. The context-cut straddle snap guarantees no entity has
        ``end > hi``, so the forward edge never splits one. An entity whose head
        reaches back into the already-emitted left-context (``start < lo``) is
        CLAMPED (``start → lo`` via ``max(0, …)``): its head is committed
        plaintext we cannot rewrite, but its in-range tail is still redacted —
        the direct-PII pattern that only completed once the retained
        left-context joined it.

        For a clamped straddler the ``text`` is also TRUNCATED to its in-range
        tail (drop the ``lo − start`` head chars), so the fake maps to exactly
        the chars the emit range covers. Without this the key would map
        ``fake → full original`` while only the tail is spliced, and restore
        would expand the fake back over the already-emitted head — a round-trip
        corruption. Entities are non-overlapping (merged), so at most one
        straddles ``lo`` and the clamp can never overlap a neighbour.
        """
        result = []
        for e in entities:
            if lo < e.end <= hi:
                drop = max(0, lo - e.start)  # head chars in the left-context
                text = e.text[drop:] if drop else e.text
                result.append(
                    dataclasses.replace(
                        e, start=max(0, e.start - lo), end=e.end - lo, text=text
                    )
                )
        return result

    def _redact_and_merge(
        self, text: str, entities: list[PatternMatch] | None
    ) -> PseudonymLLMResult:
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
            # ``None`` on the forced bounded-drain split → redact_pseudonym_llm
            # re-detects the bare emit slice internally (pre-rework drain safety);
            # otherwise the range-shifted full-buffer detection.
            _pre_detected=entities,
            # Mid-stream slices are fresh original text, but pass
            # _polluted_input_ok=True since the eager check in feed() already
            # guards against pollution and avoids a redundant scan.
            _polluted_input_ok=True,
        )
        # setdefault preserves first-seen mapping; realistic and audit spaces
        # are disjoint by construction, so collisions are impossible.
        for fake, original in result.key.items():
            self._accumulated_key.setdefault(fake, original)
        return result

    def aggregate_key(self) -> dict[str, str]:
        """Return a copy of the unified key across all fed chunks."""
        return dict(self._accumulated_key)

    def export_state(self, *, include_salt: bool = False) -> dict:
        """Serialize this redactor's state to a JSON-friendly dict.

        ⚠️ The salt is the cryptographic root of trust — by default v0.6.2+
        excludes it from the output. ``accumulated_key`` still carries
        plaintext originals; encrypt the dict at rest if persisted.

        Pass ``include_salt=True`` for v0.6.0/v0.6.1-shaped exports (deprecated;
        will be removed in v0.7.0). Prefer storing the salt out-of-band and
        passing it to ``from_state(state, salt=...)`` on resume.
        """
        state = {
            "version": _STATE_SCHEMA_VERSION,
            "accumulated_key": dict(self._accumulated_key),
            # In-flight tail accumulated past the last sentence boundary. Must be
            # carried across a checkpoint or end-of-stream text is silently lost
            # on resume. Additive field — older (field-less) dumps load fine via
            # the .get("inc_buffer", "") default in from_state, so no version bump.
            "inc_buffer": self._inc_buffer,
            # Length of the already-emitted left-context prefix retained at the
            # front of inc_buffer. Additive field with default 0 — older dumps
            # load cleanly via .get("ctx_len", 0), no version bump.
            "ctx_len": self._ctx_len,
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
        if include_salt:
            warnings.warn(
                "export_state(include_salt=True) is deprecated and will be "
                "removed in v0.7.0; pass salt to from_state(state, salt=...) "
                "instead. Embedding the salt in the serialized dict makes the "
                "cryptographic root of trust trivially recoverable from any "
                "leaked dump.",
                DeprecationWarning,
                stacklevel=2,
            )
            state["salt"] = self._salt.hex()
        return state

    @classmethod
    def from_state(cls, state: dict, *, salt: bytes | None = None) -> "StreamingRedactor":
        """Rebuild a StreamingRedactor from a previously exported state dict.

        ``salt`` is required — pass the value held out-of-band when the state
        was exported. v0.6.0/v0.6.1 dumps that embed ``state["salt"]`` still
        load (with DeprecationWarning) for back-compat; explicit ``salt=``
        kwarg always wins if both are present.
        """
        version = state.get("version")
        if version != _STATE_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported state schema version {version!r}; this release "
                f"reads schema {_STATE_SCHEMA_VERSION} only."
            )
        salt = _resolve_state_salt(state, salt)
        reserved = state.get("reserved_names")
        instance = cls(
            salt=salt,
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
        instance._inc_buffer = state.get("inc_buffer", "")
        instance._ctx_len = state.get("ctx_len", 0)
        return instance
