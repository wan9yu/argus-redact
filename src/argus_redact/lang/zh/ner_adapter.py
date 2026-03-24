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
        try:
            start = text.index(token, pos)
        except ValueError:
            return offsets  # partial mapping on failure
        end = start + len(token)
        offsets.append((start, end))
        pos = end
    return offsets


def _find_entity_in_text(
    text: str,
    entity_text: str,
    search_start: int = 0,
) -> tuple[int, int] | None:
    """Find entity text in original text, returning (start, end) or None."""
    idx = text.find(entity_text, search_start)
    if idx == -1:
        return None
    return idx, idx + len(entity_text)


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
        if not text:
            return []
        if self._model is None:
            self.load()

        result = self._model(text)
        ner_results = result.get("ner/msra", [])
        tokens = result.get("tok/fine", [])

        char_offsets = _token_to_char_offsets(text, tokens) if tokens else []

        entities = []
        seen_positions: set[tuple[int, int]] = set()

        for item in ner_results:
            entity_text, label, tok_start, tok_end = item
            mapped_type = _TYPE_MAP.get(label)
            if mapped_type is None:
                continue

            # Convert token offsets to character offsets
            char_start, char_end = None, None
            if char_offsets and tok_start < len(char_offsets) and 0 < tok_end <= len(char_offsets):
                char_start = char_offsets[tok_start][0]
                char_end = char_offsets[tok_end - 1][1]

            # Validate: extracted text must match entity text
            if char_start is not None and text[char_start:char_end] != entity_text:
                char_start, char_end = None, None

            # Fallback: search for entity text
            if char_start is None:
                found = _find_entity_in_text(text, entity_text)
                if found is None:
                    continue
                char_start, char_end = found

            # Skip if out of bounds
            if char_end > len(text):
                continue

            # Dedup same position
            pos = (char_start, char_end)
            if pos in seen_positions:
                continue
            seen_positions.add(pos)

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
