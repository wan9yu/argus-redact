"""Shared type definitions."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PatternMatch:
    """A PII match detected by regex pattern."""

    text: str
    type: str
    start: int
    end: int
    confidence: float = 1.0
