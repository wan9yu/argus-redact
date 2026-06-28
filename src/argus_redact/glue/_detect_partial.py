"""Private carry-window helpers for incremental streaming.

The carry-window STATE MACHINE lives in the Rust core
(``_core.streaming_*``), which is the SSOT — the same engine the wasm
crate exposes. This module provides Python-level helpers:

- ``_last_boundary_index`` — thin shim over ``_core.streaming_last_boundary_index``.
- ``_context_cut`` — detect once over the full buffer and pick the
  detection-context emit cut (used by ``StreamingRedactor.feed`` / ``flush``).

Used by ``StreamingRedactor``. See ``docs/design-streaming-incremental.md``.
"""

from __future__ import annotations

from argus_redact._core_loader import _core
from argus_redact._types import PatternMatch
from argus_redact.glue.redact import _detect

# Maximum buffer size before forcing a flush on input without sentence
# punctuation. Shared with ``StreamingRedactor`` so they enforce the same bound.
# Mirrors ``_core.streaming`` ``DEFAULT_MAX_BUFFER``.
DEFAULT_MAX_BUFFER = 4096

# Detection-context window W (CHARS) held on each side of every emit so
# streaming detection equals batch detection for the evidence-gated L1
# detectors (region/occupation/condition/hobby). Mirrors
# ``_core.streaming.EVIDENCE_CONTEXT_WINDOW`` parity-by-convention.
_EVIDENCE_CONTEXT_WINDOW = 128

# Extra CHARS added to max_buffer while a PEM private-key BEGIN marker is present
# in the buffer. Mirrors ``PEM_OPENER_CEILING_EXTRA`` in the Rust core. Keeps a
# complete (BEGIN+END) key whose byte length exceeds DEFAULT_MAX_BUFFER from being
# force-flush-split by context_cut's bounded-drain. The raise is gated on any
# private-key BEGIN present (closed OR unclosed) via
# ``_core.streaming_pem_begin_present`` — the SAME predicate (literal AND
# private-key regex) the wasm path uses, so wheel and wasm pick the same cut on a
# non-private-key PEM block (e.g. ``-----BEGIN CERTIFICATE-----``).
_PEM_OPENER_CEILING_EXTRA = 11_000


def _last_boundary_index(text: str) -> int:
    """Index *after* the rightmost REAL sentence-boundary char in ``text``. -1 if none.

    Thin shim over ``_core.streaming_last_boundary_index`` (the SSOT). A boundary
    char must mark a genuine sentence end, not an intra-entity char:

    - ``\\n`` and the CJK full-width boundaries (``。``/``！``/``？``/``；``) ALWAYS
      count — they never appear inside ASCII entities and CJK sentences have no
      trailing space, so they are unambiguous even at the buffer end.
    - The ASCII boundaries (``.``/``!``/``?``/``;``) count ONLY when the NEXT char
      in the buffer is whitespace. An ASCII boundary at the BUFFER END (no next
      char yet) does NOT count — it is ambiguous (``. `` sentence-end vs ``.com``
      intra-entity); wait for the next chunk to disambiguate.

    Keeps the "index after the boundary char" contract.
    """
    return _core.streaming_last_boundary_index(text)



def _context_cut(
    combined: str,
    ctx_len: int,
    *,
    lang: str | list[str],
    mode: str,
    names: list[str] | None,
    types: list[str] | None,
    types_exclude: list[str] | None,
    max_buffer: int = DEFAULT_MAX_BUFFER,
    force_flush: bool = False,
) -> tuple[int, bool, list[PatternMatch]]:
    """Detect once over the full buffer and pick the detection-context emit cut.

    Returns ``(cut_char_index, redetect, entities)`` where ``cut_char_index`` is
    the CHAR index in ``combined`` up to which it is safe to emit (``cut ==
    ctx_len`` means nothing new is safe yet) and ``entities`` are all detected
    entities over the FULL buffer (with ±W of context) in absolute buffer
    coordinates.

    ``redetect`` is ``True`` only on the forced bounded-drain split (a
    ≥ ``max_buffer`` boundary-less mega-entity whose span runs from ``ctx_len``
    past the drain point): the caller must RE-DETECT the emit slice rather than
    range-shift ``entities`` (the full-buffer straddler would be dropped, leaking
    its head raw). Every other cut leaves it ``False``.

    The cut is the last real sentence boundary that leaves ≥ W chars of forward
    context (``safe_end = len − W ≥ ctx_len``), snapped off any straddled entity
    via ``_core.streaming_context_cut``. An in-flight PEM opener is treated as
    an open-ended entity spanning ``[begin, len+1)`` so the snap holds the cut
    before BEGIN.

    Used by ``StreamingRedactor.feed`` / ``flush`` for detect-once-then-redact-
    range: one detection pass per round drives both the cut decision AND the
    redaction (no re-detect of the bare emit slice — except on the ``redetect``
    drain path).
    """
    entities, _langs, _timing, _stats = _detect(
        combined,
        lang=lang,
        mode=mode,
        names=names,
        types=types,
        types_exclude=types_exclude,
    )
    spans = [(e.start, e.end, e.type) for e in entities]
    # An in-flight PEM private key (BEGIN seen, END not yet) is not a detected
    # entity; append an open-ended pending span so context_cut holds the cut
    # before BEGIN and the whole key accumulates until END (never emitted raw).
    begin = _core.streaming_unclosed_pem_opener_start(combined)
    if begin is not None:
        spans.append((begin, len(combined) + 1, "ssh_private_key"))
    # Raise the max_buffer ceiling while any PEM private-key BEGIN is present
    # (opened or closed) so a complete key larger than DEFAULT_MAX_BUFFER is
    # carried whole rather than force-flush-split. Gated on the SAME predicate the
    # wasm path uses (literal AND private-key regex) so wheel and wasm pick the
    # same cut on a non-private-key PEM block.
    effective_max = (
        max_buffer + _PEM_OPENER_CEILING_EXTRA
        if _core.streaming_pem_begin_present(combined)
        else max_buffer
    )
    cut, redetect = _core.streaming_context_cut(
        combined, spans, ctx_len, effective_max, _EVIDENCE_CONTEXT_WINDOW, force_flush
    )
    return cut, redetect, entities


