"""English Layer 1 PII patterns — thin re-export of ``specs/en.py``."""

from argus_redact.specs.en import build_patterns

PATTERNS = build_patterns()

__all__ = ["PATTERNS"]
