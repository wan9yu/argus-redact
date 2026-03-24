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


def _token_to_char_offsets(text: str, tokens: list[str]) -> list[tuple[int, int]]:
    """Map token list to character offset pairs in the original text."""
    offsets = []
    pos = 0
    for token in tokens:
        start = text.index(token, pos)
        end = start + len(token)
        offsets.append((start, end))
        pos = end
    return offsets


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
        tokens = result.get("tok/fine", [])

        # Build token-to-char offset mapping
        if tokens:
            char_offsets = _token_to_char_offsets(text, tokens)
        else:
            char_offsets = []

        entities = []
        for item in ner_results:
            entity_text, label, tok_start, tok_end = item
            mapped_type = _TYPE_MAP.get(label)
            if mapped_type is None:
                continue

            # Convert token offsets to character offsets
            if char_offsets and tok_start < len(char_offsets) and tok_end - 1 < len(char_offsets):
                char_start = char_offsets[tok_start][0]
                char_end = char_offsets[tok_end - 1][1]
            else:
                # Fallback: search for entity text in original text
                idx = text.find(entity_text)
                if idx == -1:
                    continue
                char_start = idx
                char_end = idx + len(entity_text)

            entities.append(
                NEREntity(
                    text=entity_text,
                    type=mapped_type,
                    start=char_start,
                    end=char_end,
                    confidence=_DEFAULT_CONFIDENCE,
                )
            )

        return entities


def create_adapter() -> HanLPAdapter:
    return HanLPAdapter()
