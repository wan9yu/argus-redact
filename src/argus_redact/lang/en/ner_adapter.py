"""spaCy English NER adapter."""

from __future__ import annotations

from argus_redact._types import NEREntity
from argus_redact.impure.ner import NERAdapter

_TYPE_MAP = {
    "PERSON": "person",
    "GPE": "location",
    "LOC": "location",
    "ORG": "organization",
    "FAC": "location",
    "NORP": "organization",
}

_DEFAULT_CONFIDENCE = 0.85


class SpaCyAdapter(NERAdapter):
    """English NER using spaCy (en_core_web_sm)."""

    # Marks this adapter's `person` candidates for L1-evidence gating in the L2
    # glue. spaCy English NER is high-recall/noisy on prose; ungated, its `person`
    # spans wreck precision. The glue routes them through the SAME Rust evidence
    # scorer L1 uses (`person_en::score_person_candidate`).
    lang = "en"

    def __init__(self):
        self._nlp = None

    def load(self) -> None:
        if self._nlp is not None:
            return
        import spacy

        self._nlp = spacy.load("en_core_web_sm")

    def detect(self, text: str) -> list[NEREntity]:
        if not text:
            return []
        if self._nlp is None:
            self.load()

        doc = self._nlp(text)
        entities = []

        for ent in doc.ents:
            mapped_type = _TYPE_MAP.get(ent.label_)
            if mapped_type is None:
                continue
            entities.append(
                NEREntity(
                    text=ent.text,
                    type=mapped_type,
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=_DEFAULT_CONFIDENCE,
                )
            )

        return entities


def create_adapter() -> SpaCyAdapter:
    return SpaCyAdapter()
