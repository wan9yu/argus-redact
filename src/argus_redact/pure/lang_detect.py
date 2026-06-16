"""Script-based language detection — thin wrapper over the Rust core."""
from __future__ import annotations

from argus_redact._core import detect_languages

__all__ = ["detect_languages"]
