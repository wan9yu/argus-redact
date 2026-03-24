"""NER adapter interface and detect_ner() function."""

from __future__ import annotations

from argus_redact._types import NEREntity


class NERAdapter:
    """Base class for NER model adapters.

    Subclass and implement load() and detect() for each language backend.
    """

    def load(self) -> None:
        raise NotImplementedError

    def detect(self, text: str) -> list[NEREntity]:
        raise NotImplementedError


def detect_ner(
    text: str,
    *,
    adapter: NERAdapter,
    min_confidence: float = 0.5,
) -> list[NEREntity]:
    """Run NER on text using the given adapter, filter by confidence."""
    if not text:
        return []

    entities = adapter.detect(text)

    return [e for e in entities if e.confidence >= min_confidence]
