"""NER adapter interface and detect_ner() function."""

from __future__ import annotations

from argus_redact._types import NEREntity


class NERAdapter:
    """Base class for NER model adapters.

    Subclass and implement load() and detect() for each language backend.

    ``lang`` is the language code an adapter detects for (``None`` on the base).
    The L2 glue reads it to apply language-specific candidate gating — currently
    only the English (``"en"``) adapter, whose high-recall spaCy ``person`` spans
    are routed through the L1 evidence gate before they enter the result set.
    """

    lang: str | None = None

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
