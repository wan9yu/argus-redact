"""spaCy German NER adapter (de_core_news_sm)."""

from __future__ import annotations

from argus_redact.lang.shared.spacy_adapter import _SpaCyNERAdapter

_TYPE_MAP = {
    "PER": "person",
    "PERSON": "person",
    "LOC": "location",
    "GPE": "location",
    "ORG": "organization",
    "MISC": "organization",
}

_DEFAULT_CONFIDENCE = 0.80


class GermanNERAdapter(_SpaCyNERAdapter):
    """German NER using spaCy (de_core_news_sm)."""

    _MODEL = "de_core_news_sm"
    _TYPE_MAP = _TYPE_MAP
    _DEFAULT_CONFIDENCE = _DEFAULT_CONFIDENCE


def create_adapter() -> GermanNERAdapter:
    return GermanNERAdapter()
