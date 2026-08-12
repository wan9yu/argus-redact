"""spaCy UK English NER adapter (en_core_web_sm)."""

from __future__ import annotations

from argus_redact.lang.shared.spacy_adapter import _SpaCyNERAdapter

_TYPE_MAP = {
    "PERSON": "person",
    "GPE": "location",
    "LOC": "location",
    "ORG": "organization",
    "FAC": "location",
}

_DEFAULT_CONFIDENCE = 0.80


class UKNERAdapter(_SpaCyNERAdapter):
    """UK English NER using spaCy (en_core_web_sm)."""

    _MODEL = "en_core_web_sm"
    _TYPE_MAP = _TYPE_MAP
    _DEFAULT_CONFIDENCE = _DEFAULT_CONFIDENCE


def create_adapter() -> UKNERAdapter:
    return UKNERAdapter()
