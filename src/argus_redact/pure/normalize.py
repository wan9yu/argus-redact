"""Unicode normalization for PII detection — thin wrapper over the Rust core.

normalize_text strips invisibles, folds Cyrillic/Greek confusables, applies NFKC,
and converts Chinese-digit sequences; returns (normalized, offset_map). The heavy
lifting is in argus-redact-core; this module preserves the public API + MAX_INPUT_SIZE.
"""
from __future__ import annotations

from argus_redact._core import map_spans_to_original as _core_map
from argus_redact._core import normalize_text

MAX_INPUT_SIZE = 1024 * 1024  # 1MB

__all__ = ["normalize_text", "map_spans_to_original", "MAX_INPUT_SIZE"]


def map_spans_to_original(spans, offset_map, original_len):
    # _core expects list[tuple]; glue passes list of (start, end)
    return [tuple(s) for s in _core_map(list(spans), offset_map, original_len)]
