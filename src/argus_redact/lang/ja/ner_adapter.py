"""spaCy Japanese NER adapter (ja_core_news_sm)."""

from __future__ import annotations

from argus_redact.lang.shared.spacy_adapter import _SpaCyNERAdapter

_TYPE_MAP = {
    "PERSON": "person",
    "GPE": "location",
    "LOC": "location",
    "ORG": "organization",
    "FAC": "location",
    "PRODUCT": "organization",
    "EVENT": "event",
}

_DEFAULT_CONFIDENCE = 0.80


class JapaneseNERAdapter(_SpaCyNERAdapter):
    """Japanese NER using spaCy (ja_core_news_sm)."""

    _MODEL = "ja_core_news_sm"
    _TYPE_MAP = _TYPE_MAP
    _DEFAULT_CONFIDENCE = _DEFAULT_CONFIDENCE


def create_adapter() -> JapaneseNERAdapter:
    return JapaneseNERAdapter()
