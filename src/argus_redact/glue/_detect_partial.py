"""Private partial-detection helper for incremental streaming (v0.5.7+).

`_detect_partial(text, prev_buffer="")` accumulates `text` into the buffer
and emits entities up to the last sentence boundary; the unconsumed tail
is returned as the new buffer state. `force_flush=True` emits everything
regardless of boundary state — used by ``StreamingRedactor`` /
``StreamingRestorer`` internally at end-of-stream.

Used by ``StreamingRedactor`` (which since v0.6.0 runs incremental
detection unconditionally). See ``docs/design-streaming-incremental.md``.
"""

from __future__ import annotations

from argus_redact._types import PatternMatch
from argus_redact.glue.redact import _detect

# Sentence boundaries — last char of completed unit. Aligned with
# ``StreamingRestorer.BOUNDARIES`` so the two layers agree on chunk semantics.
_BOUNDARIES = ("\n", "。", ".", "！", "!", "？", "?", "；", ";")

# Boundary chars that ALWAYS terminate a sentence: ``\n`` and the CJK full-width
# punctuation. They never appear inside an ASCII entity (email/IPv4 use ``.``),
# and CJK sentences have no trailing space, so a CJK boundary is unambiguous even
# at the buffer end.
_ALWAYS_BOUNDARIES = frozenset("\n。！？；")

# The ASCII boundary chars. ``.``/``!``/``?``/``;`` double as intra-entity chars
# (an email/IPv4 dot, ``a;b`` in some tokens), so they count as a sentence end
# ONLY when the next buffer char is whitespace — and never at the buffer end,
# where the next char is unknown (could be ``. `` sentence-end or ``.com``).
_ASCII_BOUNDARIES = frozenset(".!?;")
_WHITESPACE = frozenset(" \t\n")

# Maximum buffer size before forcing a flush on input without sentence
# punctuation. Shared between ``_detect_partial`` and ``StreamingRedactor``
# so they enforce the same bound.
DEFAULT_MAX_BUFFER = 4096

# Trailing window carried into the next chunk at a boundary-less force-flush
# (buffer ≥ ``max_buffer`` with no sentence boundary). Without it the whole
# buffer emits and an entity straddling the cut is split across two emits —
# neither half matches its pattern, so the head leaks (a real PII leak).
# Carrying this window keeps any near-cut entity wholly present next round.
#
# It must be ≥ the longest BOUNDED entity span so a straddling entity always
# fits inside the carried region: org/school suffixes (~≤20 chars), street
# addresses, IBAN (≤34), GB national ID (18). 256 is a generous margin.
#
# UNBOUNDED tokens (a JWT / base64 run longer than this window) are the
# documented residual edge: a token that exceeds the window can still be split
# at the force-flush cut. Bounded PII — the entity types this library detects —
# is covered.
_CARRY_WINDOW = 256


def _last_boundary_index(text: str) -> int:
    """Index *after* the rightmost REAL sentence-boundary char in ``text``. -1 if none.

    A boundary char must mark a genuine sentence end, not an intra-entity char:

    - ``\\n`` and the CJK full-width boundaries (``。``/``！``/``？``/``；``) ALWAYS
      count — they never appear inside ASCII entities and CJK sentences have no
      trailing space, so they are unambiguous even at the buffer end.
    - The ASCII boundaries (``.``/``!``/``?``/``;``) count ONLY when the NEXT char
      in the buffer is whitespace. An ASCII boundary at the BUFFER END (no next
      char yet) does NOT count — it is ambiguous (``. `` sentence-end vs ``.com``
      intra-entity); wait for the next chunk to disambiguate.

    Keeps the "index after the boundary char" contract.
    """
    n = len(text)
    for pos in range(n - 1, -1, -1):
        ch = text[pos]
        if ch in _ALWAYS_BOUNDARIES:
            return pos + 1
        if ch in _ASCII_BOUNDARIES:
            # Real sentence end only if followed by whitespace; at the buffer end
            # the next char is unknown → ambiguous, keep scanning leftward.
            if pos + 1 < n and text[pos + 1] in _WHITESPACE:
                return pos + 1
    return -1


def _bounded_carry(combined: str, max_buffer: int) -> tuple[str, str]:
    """cut<=0: a span longer than the carry window blocks a safe cut. To
    guarantee the buffer drains (no unbounded growth / O(n^2) / MAX_INPUT_SIZE
    crash), once the buffer reaches max_buffer force-emit the prefix down to the
    trailing carry window. Such a span is necessarily longer than _CARRY_WINDOW
    (a bounded entity would have yielded cut>0) -- i.e. the documented >window
    unbounded-token edge. A still-small buffer is safe to carry whole; it will
    grow to max_buffer and drain here next round."""
    if len(combined) >= max_buffer:
        target = len(combined) - _CARRY_WINDOW
        return combined[:target], combined[target:]
    return "", combined


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

    With ``force_flush=True`` (end-of-stream) the entire combined string emits
    and residual is empty. With a boundary-less buffer ≥ ``max_buffer`` a
    trailing ``_CARRY_WINDOW`` is carried instead of emitting everything, so an
    entity straddling the cut stays whole for next round (see ``_CARRY_WINDOW``).
    The cut is snapped back so it never splits a detected entity; the detection
    params (``lang``/``mode``/``names``/``types``/``types_exclude``) must match
    the caller's so the carry decision agrees with the caller's own detection.
    """
    combined = prev_buffer + chunk
    if not combined:
        return "", ""
    if force_flush:
        return combined, ""
    boundary = _last_boundary_index(combined)
    if boundary < 0:
        if len(combined) >= max_buffer:
            # Boundary-less force-flush. Carry a trailing window so a straddling
            # entity is whole next round. Tiny buffers (≤ window) carry all
            # rather than slicing a negative index.
            if len(combined) <= _CARRY_WINDOW:
                return "", combined
            target = len(combined) - _CARRY_WINDOW
            cut = _carry_cut_index(
                combined,
                target,
                lang=lang,
                mode=mode,
                names=names,
                types=types,
                types_exclude=types_exclude,
            )
            if cut <= 0:
                # An entity spans from the buffer start past the window. We are
                # already at len(combined) >= max_buffer, so force a bounded
                # drain (down to the trailing window) rather than carrying all —
                # carrying all here let an open-ended span grow the buffer
                # without bound (O(n^2) re-detect, then a MAX_INPUT_SIZE crash).
                # Such a span is necessarily longer than _CARRY_WINDOW — the
                # documented >window unbounded-token edge; its head is emitted.
                return _bounded_carry(combined, max_buffer)
            return combined[:cut], combined[cut:]
        return "", combined
    # boundary >= 0: a real sentence end. Even so it can sit inside a detected
    # entity (e.g. an address "123 Main St. Apt 4" where "St. " is a real
    # boundary). Apply the same entity-aware snap as the force-flush path: if an
    # entity straddles the boundary, snap the cut back to its start and carry it
    # whole. cut <= 0 (entity spans from the buffer start past the boundary) →
    # carry all; it resolves at a later boundary or the end-of-stream flush.
    cut = _carry_cut_index(
        combined,
        boundary,
        lang=lang,
        mode=mode,
        names=names,
        types=types,
        types_exclude=types_exclude,
    )
    if cut <= 0:
        # An entity spans from the buffer start past the boundary. Carrying all
        # here would let an open-ended span that keeps extending across each new
        # boundary grow the buffer without bound; gate the drain on max_buffer
        # via the same bounded-carry guard as the force-flush path. A small
        # buffer is still carried whole and resolves at a later boundary.
        return _bounded_carry(combined, max_buffer)
    return combined[:cut], combined[cut:]


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
