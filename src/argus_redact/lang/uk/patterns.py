"""UK Layer-1 PII patterns — thin reader of the Rust core (RON) SSOT."""

from argus_redact.lang._loader import core_patterns

PATTERNS = core_patterns("uk")

__all__ = ["PATTERNS"]
