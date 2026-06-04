"""argus_redact.compose — Layer 2 best-effort helpers built ON TOP of the primitive.

This namespace consolidates the public surface of the "compose" layer per
docs/architecture-layers.md §Layer 2:

- StreamingRedactor / StreamingRestorer — sentence-buffered streaming
  (re-exported from argus_redact.streaming)
- redact_pseudonym_llm — three-form output (audit / downstream / display)
  (re-exported from argus_redact.glue.redact_pseudonym_llm)
- prompt_anchor — input-side system-prompt addendum
- expand_aliases — output-side surname+title alias expansion

The top-level argus_redact.{StreamingRedactor, redact_pseudonym_llm} aliases
remain functional. StreamingRestorer was never top-level — argus_redact.compose
is its first public path. Migration to compose-canonical imports is
recommended but not enforced in v0.6.7.
"""

from __future__ import annotations

from argus_redact.compose.aliases import expand_aliases
from argus_redact.compose.anchor import prompt_anchor
from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm
from argus_redact.streaming import StreamingRedactor, StreamingRestorer

__all__ = [
    "StreamingRedactor",
    "StreamingRestorer",
    "redact_pseudonym_llm",
    "prompt_anchor",
    "expand_aliases",
]
