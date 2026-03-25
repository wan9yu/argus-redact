"""spaCy multilingual NER adapter for Indian English (xx_ent_wiki_sm)."""

from __future__ import annotations

from argus_redact._types import NEREntity
from argus_redact.impure.ner import NERAdapter

_TYPE_MAP = {
    "PER": "person",
    "PERSON": "person",
    "LOC": "location",
    "GPE": "location",
    "ORG": "organization",
}

_DEFAULT_CONFIDENCE = 0.75


class IndianNERAdapter(NERAdapter):
    """Indian English NER using spaCy multilingual (xx_ent_wiki_sm)."""

    def __init__(self):
        self._nlp = None

    def load(self) -> None:
        if self._nlp is not None:
            return
        import spacy

        self._nlp = spacy.load("xx_ent_wiki_sm")

    def detect(self, text: str) -> list[NEREntity]:
        if not text:
            return []
        if self._nlp is None:
            self.load()

        doc = self._nlp(text)
        return [
            NEREntity(
                text=ent.text,
                type=_TYPE_MAP[ent.label_],
                start=ent.start_char,
                end=ent.end_char,
                confidence=_DEFAULT_CONFIDENCE,
            )
            for ent in doc.ents
            if ent.label_ in _TYPE_MAP
        ]


def create_adapter() -> IndianNERAdapter:
    return IndianNERAdapter()
