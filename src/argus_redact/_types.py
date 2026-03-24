"""Shared type definitions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PatternMatch:
    """A PII match detected by regex pattern or NER."""

    text: str
    type: str
    start: int
    end: int
    confidence: float = 1.0


@dataclass(frozen=True)
class NEREntity:
    """An entity detected by NER model."""

    text: str
    type: str
    start: int
    end: int
    confidence: float

    def to_pattern_match(self) -> PatternMatch:
        return PatternMatch(
            text=self.text,
            type=self.type,
            start=self.start,
            end=self.end,
            confidence=self.confidence,
        )
