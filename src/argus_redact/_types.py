"""Shared type definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from argus_redact._core_loader import _core

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


# The Rust ``_core.PatternMatch`` the PyO3 boundary exchanges (resolved once at
# import, the same idiom the pure marshalling modules used). ``to_rust_pm`` /
# ``from_rust_pm`` are THE single conversion between the frozen dataclass above
# and that Rust type — every FFI hop (person shims, merger, coverage restorer,
# replacer) marshals through them so the field order and value mapping cannot
# drift from one call site to the next.
_RustPM = _core.PatternMatch


def to_rust_pm(pm: PatternMatch) -> "_RustPM":
    """Marshal a Python ``PatternMatch`` into the Rust ``_core.PatternMatch`` the
    FFI expects. Positional field order matches the Rust constructor."""
    return _RustPM(pm.text, pm.type, pm.start, pm.end, pm.confidence, pm.layer)


def from_rust_pm(e: "_RustPM") -> PatternMatch:
    """Rebuild a Python ``PatternMatch`` from a Rust ``_core.PatternMatch`` handed
    back across the FFI boundary — the inverse of :func:`to_rust_pm`."""
    return PatternMatch(
        text=e.text,
        type=e.type,
        start=e.start,
        end=e.end,
        confidence=e.confidence,
        layer=e.layer,
    )


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
class CoverageAdvisory:
    """What this configuration could NOT have found.

    Derived from ``(lang, mode)`` alone — it does not inspect the text and makes
    no claim about this document. It is the denominator that makes an empty
    result readable: "we found nothing" means something different when the
    configuration had no detector for half the categories in the first place.

    Named ``CoverageAdvisory`` rather than ``ResidualAdvisory`` deliberately.
    "Residual" would imply a finding about what survived this document; this is
    a capability declaration. A name that overstates is the hardest kind of
    error to catch later.
    """

    uncovered: tuple[str, ...] = ()
    """Categories with no detector at all under this configuration."""

    narrow: tuple[str, ...] = ()
    """Categories detected only in some forms, or only as a different type."""

    exhaustive: bool = False
    """Always ``False``. The taxonomy is not exhaustive of what can re-identify
    a person, so this is a field rather than a sentence in the docs — consumers
    read fields."""


@dataclass(frozen=True)
class RedactReport:
    """Structured audit report from redact(report=True)."""

    redacted_text: str
    key: dict[str, str]
    entities: tuple[dict, ...] = ()
    stats: dict = field(default_factory=dict)
    risk: RiskResult | None = None
    residual_personal_data: bool = True
    security_events: tuple[dict, ...] = ()
    coverage: CoverageAdvisory | None = None
    layers_used: tuple[int, ...] = ()


@dataclass(frozen=True)
class PseudonymLLMResult:
    """Result of redact_pseudonym_llm() — three text forms sharing one key dict.

    Public access:
    - ``result.key`` — ``str → str`` dict (fake → original).
    - ``result.aliases`` *(v0.6.0+)* — ``str → tuple[str, ...]`` dict mapping a
      fake to alternate transliterations a downstream LLM might emit. Pass
      ``aliases`` to ``restore()`` for cross-language recovery.
    - ``result.types`` — ``str → str`` dict (fake → SSOT PII type). The SAME
      canonical type names ``redact(with_types=True)`` returns, e.g.
      ``"bank_card"``, ``"person"``, ``"passport"`` — never audit-prefix
      reverse-parse fragments (``"cn_bank_card"``, ``"o"``). Covers BOTH the
      realistic downstream fakes AND the ``[TYPE-NNNNN]`` audit placeholders.
      Empty when nothing was detected. (Distinct from the ``types`` *parameter*
      of ``redact_pseudonym_llm``, which is a detection type filter.)
    - ``result.downstream_key`` *(v0.8.2+)* — realistic-fake-only subset of
      ``key`` (excludes audit-space placeholders); this is what a
      streaming/multi-call caller should thread back as ``existing_key=`` so
      the realistic pass never resolves a recurring original to an audit
      placeholder.
    """

    audit_text: str
    downstream_text: str
    display_text: str
    key: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, tuple[str, ...]] = field(default_factory=dict)
    types: dict[str, str] = field(default_factory=dict)
    downstream_key: dict[str, str] = field(default_factory=dict)
