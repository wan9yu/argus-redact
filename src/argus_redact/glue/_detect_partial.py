"""Private partial-detection helper for incremental streaming (v0.5.7+).

`_detect_partial(text, prev_buffer="")` accumulates `text` into the buffer
and emits entities up to the last sentence boundary; the unconsumed tail
is returned as the new buffer state. `force_flush=True` emits everything
regardless of boundary state — used by ``StreamingRedactor`` /
``StreamingRestorer`` internally at end-of-stream.

Since the v0.7.10 → wasm port, the carry-window STATE MACHINE
(``_last_boundary_index`` / ``_bounded_carry`` / ``_consume_to_boundary``) is a
thin shim over the Rust core (``_core.streaming_*``), which is the SSOT — the same
engine the wasm crate exposes. Only the entity-aware SNAP (``_carry_cut_index``,
which detects on the full combined buffer with the caller's exact detection
params) stays in Python: it threads the Python ``_detect`` (the L1+NER+semantic
SSOT detector) and is monkeypatched by the streaming tests. The core engine calls
``_carry_cut_index`` back as a ``(combined, target) -> cut`` callable.

Used by ``StreamingRedactor`` (which since v0.6.0 runs incremental
detection unconditionally). See ``docs/design-streaming-incremental.md``.
"""

from __future__ import annotations

from argus_redact._core_loader import _core
from argus_redact._types import PatternMatch
from argus_redact.glue.redact import _detect

# Sentence-boundary chars — last char of a completed unit. Aligned with
# ``StreamingRestorer.BOUNDARIES`` so the two layers agree on the char set; both
# now apply the SAME real-boundary rule via ``_last_boundary_index`` (``\n`` + CJK
# ``。！？；`` always count; ASCII ``.!?;`` only before whitespace, never at the
# buffer end — so a fake's internal dot is not mistaken for a sentence end). Kept
# here (not derived from the core) as the documented public-ish surface the
# streaming tests import; the core mirrors the same set.
_BOUNDARIES = ("\n", "。", ".", "！", "!", "？", "?", "；", ";")

# Maximum buffer size before forcing a flush on input without sentence
# punctuation. Shared between ``_detect_partial`` and ``StreamingRedactor``
# so they enforce the same bound. Mirrors ``_core.streaming`` ``DEFAULT_MAX_BUFFER``.
DEFAULT_MAX_BUFFER = 4096

# Trailing window carried into the next chunk at a boundary-less force-flush.
# Mirrors ``_core.streaming`` ``CARRY_WINDOW``; see the core docstring for the
# straddling-entity rationale and the >window unbounded-token residual edge.
_CARRY_WINDOW = 256


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


def _bounded_carry(combined: str, max_buffer: int) -> tuple[str, str]:
    """cut<=0: a span longer than the carry window blocks a safe cut. To
    guarantee the buffer drains (no unbounded growth / O(n^2) / MAX_INPUT_SIZE
    crash), once the buffer reaches max_buffer force-emit the prefix down to the
    trailing carry window. Such a span is necessarily longer than _CARRY_WINDOW
    (a bounded entity would have yielded cut>0) -- i.e. the documented >window
    unbounded-token edge. A still-small buffer is safe to carry whole; it will
    grow to max_buffer and drain here next round.

    Thin shim over ``_core.streaming_bounded_carry`` (the SSOT)."""
    return _core.streaming_bounded_carry(combined, max_buffer)


def _carry_cut_index(
    combined: str,
    target: int,
    *,
    lang: str | list[str],
    mode: str,
    names: list[str] | None,
    types: list[str] | None,
    types_exclude: list[str] | None,
) -> int:
    """Pick a force-flush emit cut at or before ``target`` that splits no entity.

    The carry-window keeps ``combined[target:]`` for the next round, but an
    entity whose span crosses ``target`` (head before it, tail after it) would
    have its head emitted in ``combined[:target]`` and never matched in
    isolation → a leak. Detecting on the *full* ``combined`` lets us snap the
    cut back to the start of any entity that straddles ``target`` so the whole
    entity is carried instead. Returns the emit cut index (``0`` means carry
    everything — the unbounded-token residual edge where an entity covers the
    region from the buffer start past ``target``).

    Stays in Python (the detection SSOT lives here): it threads the full Python
    ``_detect`` with the caller's exact params, and the streaming tests
    monkeypatch this function directly. The core engine calls it back as a
    ``(combined, target) -> cut`` callable.
    """
    entities, _langs, _timing, _stats = _detect(
        combined,
        lang=lang,
        mode=mode,
        names=names,
        types=types,
        types_exclude=types_exclude,
    )
    cut = target
    for ent in entities:
        # An entity straddles the cut iff it starts strictly before it and ends
        # strictly after it. Snap the cut back to its start so head+tail are
        # carried together and re-detected next round.
        if ent.start < cut < ent.end:
            cut = ent.start
    return max(cut, 0)


def _consume_to_boundary(
    prev_buffer: str,
    chunk: str,
    *,
    max_buffer: int = DEFAULT_MAX_BUFFER,
    force_flush: bool = False,
    lang: str | list[str] = "zh",
    mode: str = "fast",
    names: list[str] | None = None,
    types: list[str] | None = None,
    types_exclude: list[str] | None = None,
) -> tuple[str, str]:
    """Split ``prev_buffer + chunk`` at the last sentence boundary.

    Returns ``(emit_text, residual)`` — ``emit_text`` is the committed prefix
    (or ``""`` if nothing is ready to emit yet); ``residual`` is the tail to
    carry into the next call.

    Thin shim over ``_core.streaming_consume_to_boundary`` (the carry-window SSOT).
    The entity-aware snap is threaded back as the module-level ``_carry_cut_index``
    bound to the caller's detection params, so the carry decision agrees with the
    caller's own detection (and remains monkeypatchable for the regression tests).
    With ``force_flush=True`` (end-of-stream) the entire combined string emits and
    residual is empty. With a boundary-less buffer ≥ ``max_buffer`` a trailing
    ``_CARRY_WINDOW`` is carried instead of emitting everything, so an entity
    straddling the cut stays whole for next round.
    """

    def carry_cut(combined: str, target: int) -> int:
        # Look up the module attribute fresh so a monkeypatch of
        # ``_carry_cut_index`` (the boundary-path-drain regression test) is honored.
        return _carry_cut_index(
            combined,
            target,
            lang=lang,
            mode=mode,
            names=names,
            types=types,
            types_exclude=types_exclude,
        )

    return _core.streaming_consume_to_boundary(
        prev_buffer,
        chunk,
        carry_cut,
        max_buffer=max_buffer,
        force_flush=force_flush,
    )


def _detect_partial(
    text: str,
    *,
    prev_buffer: str = "",
    lang: str | list[str] = "zh",
    mode: str = "fast",
    names: list[str] | None = None,
    types: list[str] | None = None,
    types_exclude: list[str] | None = None,
    max_buffer: int = DEFAULT_MAX_BUFFER,
    force_flush: bool = False,
) -> tuple[list[PatternMatch], str]:
    """Detect entities in ``prev_buffer + text`` up to the last sentence boundary.

    Returns ``(complete_entities, residual_buffer)``. Entity offsets are
    relative to the emitted prefix (``(prev_buffer + text)[:boundary]``).
    With ``force_flush=True`` or combined length ≥ ``max_buffer``, everything
    is emitted regardless of boundary state.
    """
    emit_text, residual = _consume_to_boundary(
        prev_buffer,
        text,
        max_buffer=max_buffer,
        force_flush=force_flush,
        lang=lang,
        mode=mode,
        names=names,
        types=types,
        types_exclude=types_exclude,
    )
    if not emit_text:
        return [], residual
    entities, _langs, _timing, _stats = _detect(
        emit_text,
        lang=lang,
        mode=mode,
        names=names,
        types=types,
        types_exclude=types_exclude,
    )
    return entities, residual
