"""Shared base for the single-model spaCy NER adapters.

The per-language spaCy adapters (en/de/ja/ko/uk/in_) differ only in four things:
the model name, the label→type map, the default confidence, and (for en) the
``lang`` gating tag. They previously carried two structurally-different but
behaviourally-identical ``detect()`` bodies — a ``.get()`` loop and a
``label in _TYPE_MAP`` comprehension. Those coincide for every one of these maps
because no mapped value is ``None``, so "``.get()`` returned ``None``" and "the
label is absent from the map" are the same condition; both forms iterate
``doc.ents`` in order and emit the same ``NEREntity`` fields for a mapped label.
This base hosts the single loop-form body; each language subclass supplies its
model name / type map / default confidence as class attributes (and ``lang``
where L2 gating applies).
"""

from __future__ import annotations

from argus_redact._types import NEREntity
from argus_redact.impure.ner import NERAdapter


class _SpaCyNERAdapter(NERAdapter):
    """Base for a single-model spaCy NER backend.

    Subclasses set the class attributes:
    - ``_MODEL`` — spaCy model name passed to ``spacy.load``.
    - ``_TYPE_MAP`` — spaCy entity label → argus PII type; labels absent from the
      map are skipped.
    - ``_DEFAULT_CONFIDENCE`` — confidence stamped on every emitted entity.
    - ``lang`` — inherited ``None`` from ``NERAdapter`` unless the subclass sets a
      gating tag (only en does today).
    """

    _MODEL: str
    _TYPE_MAP: dict[str, str]
    _DEFAULT_CONFIDENCE: float

    def __init__(self):
        self._nlp = None

    def load(self) -> None:
        if self._nlp is not None:
            return
        import spacy

        self._nlp = spacy.load(self._MODEL)

    def detect(self, text: str) -> list[NEREntity]:
        if not text:
            return []
        if self._nlp is None:
            self.load()

        doc = self._nlp(text)
        entities = []

        for ent in doc.ents:
            mapped_type = self._TYPE_MAP.get(ent.label_)
            if mapped_type is None:
                continue
            entities.append(
                NEREntity(
                    text=ent.text,
                    type=mapped_type,
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=self._DEFAULT_CONFIDENCE,
                )
            )

        return entities
