"""Indian Layer-1 PII patterns — thin reader of the Rust core (RON) SSOT."""

from argus_redact.lang._loader import core_patterns

PATTERNS = core_patterns("in")  # core lang code is "in" (module is in_ to avoid keyword clash)

__all__ = ["PATTERNS"]
