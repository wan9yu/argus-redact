"""Shared type definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argus_redact.pure.risk import RiskResult


@dataclass(frozen=True)
class PatternMatch:
    """A PII match detected by regex pattern or NER."""

    text: str
    type: str
    start: int
    end: int
    confidence: float = 1.0
    layer: int = 0  # 1=regex, 2=NER, 3=semantic


@dataclass(frozen=True)
class Hint:
    """Cross-layer hint passed between detection layers.

    Produced by earlier layers, consumed by later layers to improve
    detection accuracy and enable context-aware decisions.
    """

    type: str  # hint category (e.g. "self_reference_tier")
    data: dict = field(default_factory=dict)  # hint-specific payload
    region: tuple[int, int] = (0, 0)  # (start, end) in original text, (0,0) = global
    source_layer: int = 1  # which layer produced this hint


@dataclass(frozen=True)
class NEREntity:
    """An entity detected by NER model."""

    text: str
    type: str
    start: int
    end: int
    confidence: float

    def to_pattern_match(self, layer: int = 2) -> PatternMatch:
        return PatternMatch(
            text=self.text,
            type=self.type,
            start=self.start,
            end=self.end,
            confidence=self.confidence,
            layer=layer,
        )


@dataclass(frozen=True)
class RedactReport:
    """Structured audit report from redact(report=True)."""

    redacted_text: str
    key: dict[str, str]
    entities: tuple[dict, ...] = ()
    stats: dict = field(default_factory=dict)
    risk: RiskResult | None = None
