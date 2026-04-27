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

# Maximum buffer size before forcing a flush on input without sentence
# punctuation. Shared between ``_detect_partial`` and
# ``StreamingRedactor(incremental=True)`` so they enforce the same bound.
DEFAULT_MAX_BUFFER = 4096


def _last_boundary_index(text: str) -> int:
    """Index *after* the rightmost sentence-boundary char in `text`. -1 if none."""
    best = -1
    for ch in _BOUNDARIES:
        pos = text.rfind(ch)
        if pos > best:
            best = pos
    return best + 1 if best >= 0 else -1


def _consume_to_boundary(
    prev_buffer: str,
    chunk: str,
    *,
    max_buffer: int = DEFAULT_MAX_BUFFER,
    force_flush: bool = False,
) -> tuple[str, str]:
    """Split ``prev_buffer + chunk`` at the last sentence boundary.

    Returns ``(emit_text, residual)`` — ``emit_text`` is the committed prefix
    (or ``""`` if nothing is ready to emit yet); ``residual`` is the tail to
    carry into the next call. With ``force_flush=True`` or buffer ≥
    ``max_buffer``, the entire combined string emits and residual is empty.
    """
    combined = prev_buffer + chunk
    if not combined:
        return "", ""
    if force_flush:
        return combined, ""
    boundary = _last_boundary_index(combined)
    if boundary < 0:
        if len(combined) >= max_buffer:
            return combined, ""
        return "", combined
    return combined[:boundary], combined[boundary:]


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
        prev_buffer, text, max_buffer=max_buffer, force_flush=force_flush
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
