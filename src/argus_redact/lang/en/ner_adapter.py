"""spaCy English NER adapter."""

from __future__ import annotations

from argus_redact.lang.shared.spacy_adapter import _SpaCyNERAdapter

_TYPE_MAP = {
    "PERSON": "person",
    "GPE": "location",
    "LOC": "location",
    "ORG": "organization",
    "FAC": "location",
    "NORP": "organization",
}

_DEFAULT_CONFIDENCE = 0.85


class SpaCyAdapter(_SpaCyNERAdapter):
    """English NER using spaCy (en_core_web_sm)."""

    # Marks this adapter's `person` candidates for L1-evidence gating in the L2
    # glue. spaCy English NER is high-recall/noisy on prose; ungated, its `person`
    # spans wreck precision. The glue routes them through the SAME Rust evidence
    # scorer L1 uses (`person_en::score_person_candidate`).
    lang = "en"
    _MODEL = "en_core_web_sm"
    _TYPE_MAP = _TYPE_MAP
    _DEFAULT_CONFIDENCE = _DEFAULT_CONFIDENCE


def create_adapter() -> SpaCyAdapter:
    return SpaCyAdapter()
