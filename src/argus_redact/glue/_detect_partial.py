"""Private partial-detection helper for incremental streaming (v0.5.7+).

`_detect_partial(text, prev_buffer="")` accumulates `text` into the buffer
and emits entities up to the last sentence boundary; the unconsumed tail
is returned as the new buffer state. `force_flush=True` emits everything
regardless of boundary state — used by ``_StreamingBuffer.flush()`` at
end-of-stream.

Used by ``_StreamingBuffer`` and the ``incremental=True`` mode of
``StreamingRedactor``. See ``docs/design-streaming-incremental.md``.
"""

from __future__ import annotations

from argus_redact._types import PatternMatch
from argus_redact.glue.redact import _detect

# Sentence boundaries — last char of completed unit. Aligned with
# ``StreamingRestorer.BOUNDARIES`` so the two layers agree on chunk semantics.
_BOUNDARIES = ("\n", "。", ".", "！", "!", "？", "?", "；", ";")


def _last_boundary_index(text: str) -> int:
    """Index *after* the rightmost sentence-boundary char in `text`. -1 if none."""
    best = -1
    for ch in _BOUNDARIES:
        pos = text.rfind(ch)
        if pos > best:
            best = pos
    return best + 1 if best >= 0 else -1


def _detect_partial(
    text: str,
    *,
    prev_buffer: str = "",
    lang: str | list[str] = "zh",
    mode: str = "fast",
    names: list[str] | None = None,
    types: list[str] | None = None,
    types_exclude: list[str] | None = None,
    max_buffer: int = 4096,
    force_flush: bool = False,
) -> tuple[list[PatternMatch], str]:
    """Detect entities in ``prev_buffer + text`` up to the last sentence boundary.

    Returns ``(complete_entities, residual_buffer)``. Entity offsets are
    relative to the emitted prefix (``(prev_buffer + text)[:boundary]``).

    With ``force_flush=True``, everything is emitted regardless of boundary
    state — required by ``_StreamingBuffer.flush()`` at end-of-stream.

    With no boundary and length ≥ ``max_buffer``, a forced flush also
    triggers — guarantees the buffer never grows without bound on input
    without sentence punctuation.
    """
    combined = prev_buffer + text
    if not combined:
        return [], ""

    if force_flush:
        boundary = len(combined)
    else:
        boundary = _last_boundary_index(combined)
        if boundary < 0:
            if len(combined) >= max_buffer:
                boundary = len(combined)
            else:
                return [], combined

    emit_text = combined[:boundary]
    residual = combined[boundary:]

    entities, _langs, _timing, _stats = _detect(
        emit_text,
        lang=lang,
        mode=mode,
        names=names,
        types=types,
        types_exclude=types_exclude,
    )
    return entities, residual
