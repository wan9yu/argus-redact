"""Semantic detection interface and detect_semantic() function."""

from __future__ import annotations

from argus_redact._types import NEREntity


class SemanticAdapter:
    """Base class for semantic (LLM-based) PII detection adapters."""

    def detect(self, text: str) -> list[NEREntity]:
        raise NotImplementedError


def detect_semantic(
    text: str,
    *,
    adapter: SemanticAdapter,
    min_confidence: float = 0.5,
) -> list[NEREntity]:
    """Run semantic PII detection using a local LLM adapter."""
    if not text:
        return []

    entities = adapter.detect(text)

    return [e for e in entities if e.confidence >= min_confidence]
