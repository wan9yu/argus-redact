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


@dataclass(frozen=True)
class KeyEntry:
    """A single fake → original mapping plus optional cross-language aliases.

    `aliases` carries transliterations the LLM might emit instead of the
    canonical fake (e.g. ``original="王建国"``, ``aliases=("Wang Jianguo",)``).
    `restore()` recognizes both the canonical fake and its aliases and maps
    them all back to ``original``.

    Tuples (not lists) so the dataclass stays hashable and frozen-friendly.
    """

    original: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class PseudonymLLMResult:
    """Result of redact_pseudonym_llm() — three text forms sharing one key.

    Public access:
    - ``result.key`` — read-only ``str → str`` dict view (fake → original).
      Backward-compatible with all v0.5.x callers.
    - ``result.key_entries`` *(v0.5.8+)* — read-only ``str → KeyEntry`` dict view
      with cross-language aliases.
    """

    audit_text: str
    downstream_text: str
    display_text: str
    _key_entries: dict[str, KeyEntry] = field(default_factory=dict, repr=False)

    @property
    def key(self) -> dict[str, str]:
        # Fresh dict per access: keeps caller mutations isolated and stays
        # ``json.dumps`` / ``isinstance(dict)`` compatible. Allocation cost is
        # O(n) per access — the typical pattern is one access per redact call,
        # so cache locally for tight loops.
        return {fake: e.original for fake, e in self._key_entries.items()}

    @property
    def key_entries(self) -> dict[str, KeyEntry]:
        # Fresh dict per access for the same reasons. KeyEntry is frozen, so
        # individual entries can't mutate.
        return dict(self._key_entries)
