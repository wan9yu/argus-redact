"""spaCy Korean NER adapter (ko_core_news_sm)."""

from __future__ import annotations

from argus_redact.lang.shared.spacy_adapter import _SpaCyNERAdapter

# Korean spaCy uses different label names
_TYPE_MAP = {
    "PS": "person",
    "PERSON": "person",
    "LC": "location",
    "GPE": "location",
    "LOC": "location",
    "OG": "organization",
    "ORG": "organization",
    "AF": "location",  # artifact/facility
}

_DEFAULT_CONFIDENCE = 0.80


class KoreanNERAdapter(_SpaCyNERAdapter):
    """Korean NER using spaCy (ko_core_news_sm)."""

    _MODEL = "ko_core_news_sm"
    _TYPE_MAP = _TYPE_MAP
    _DEFAULT_CONFIDENCE = _DEFAULT_CONFIDENCE


def create_adapter() -> KoreanNERAdapter:
    return KoreanNERAdapter()
