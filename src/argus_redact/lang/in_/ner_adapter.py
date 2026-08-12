"""spaCy multilingual NER adapter for Indian English (xx_ent_wiki_sm)."""

from __future__ import annotations

from argus_redact.lang.shared.spacy_adapter import _SpaCyNERAdapter

_TYPE_MAP = {
    "PER": "person",
    "PERSON": "person",
    "LOC": "location",
    "GPE": "location",
    "ORG": "organization",
}

_DEFAULT_CONFIDENCE = 0.75


class IndianNERAdapter(_SpaCyNERAdapter):
    """Indian English NER using spaCy multilingual (xx_ent_wiki_sm)."""

    _MODEL = "xx_ent_wiki_sm"
    _TYPE_MAP = _TYPE_MAP
    _DEFAULT_CONFIDENCE = _DEFAULT_CONFIDENCE


def create_adapter() -> IndianNERAdapter:
    return IndianNERAdapter()
