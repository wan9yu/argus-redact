"""HanLP Chinese NER adapter."""

from __future__ import annotations

from argus_redact._types import NEREntity
from argus_redact.impure.ner import NERAdapter

_TYPE_MAP = {
    "PERSON": "person",
    "LOCATION": "location",
    "ORGANIZATION": "organization",
    "GPE": "location",
    "LOC": "location",
    "ORG": "organization",
    "PER": "person",
    "NR": "person",
    "NS": "location",
    "NT": "organization",
}

_DEFAULT_CONFIDENCE = 0.85


class HanLPAdapter(NERAdapter):
    """Chinese NER using HanLP 2.x (MSRA NER)."""

    def __init__(self):
        self._model = None

    def load(self) -> None:
        if self._model is not None:
            return
        import hanlp

        model_name = hanlp.pretrained.mtl.CLOSE_TOK_POS_NER_SRL_DEP_SDP_CON_ELECTRA_BASE_ZH
        self._model = hanlp.load(model_name)

    def detect(self, text: str) -> list[NEREntity]:
        if self._model is None:
            self.load()

        result = self._model(text)
        ner_results = result.get("ner/msra", [])

        entities = []
        for item in ner_results:
            entity_text, label, start, end = item
            mapped_type = _TYPE_MAP.get(label)
            if mapped_type is None:
                continue
            entities.append(
                NEREntity(
                    text=entity_text,
                    type=mapped_type,
                    start=start,
                    end=end,
                    confidence=_DEFAULT_CONFIDENCE,
                )
            )

        return entities


def create_adapter() -> HanLPAdapter:
    return HanLPAdapter()
