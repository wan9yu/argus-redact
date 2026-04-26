"""Adapter for Kaggle PII Data Detection (PIILO) dataset.

22K real student essays with token-level BIO annotations.
HuggingFace mirror: metaboulie/Tidied-PII-Detection-Kaggle-7k (6.8K rows, Apache 2.0).
"""

from __future__ import annotations

from collections.abc import Iterator

from tests.benchmark.model import Entity, Sample

from . import register
from .base import DatasetAdapter

# Map PIILO BIO labels → argus-redact types
LABEL_MAP = {
    "NAME_STUDENT": "person",
    "EMAIL": "email",
    "USERNAME": "person",
    "ID_NUM": "id_number",
    "PHONE_NUM": "phone",
    "URL_PERSONAL": "url",
    "STREET_ADDRESS": "address",
}


def _bio_to_entities(
    tokens: list[str], labels: list[str], trailing_ws: list[bool]
) -> tuple[str, list[Entity]]:
    """Convert BIO-tagged tokens to text + entity list."""
    # Reconstruct full text with original whitespace
    parts: list[str] = []
    offsets: list[int] = []  # char offset of each token
    pos = 0
    for i, token in enumerate(tokens):
        offsets.append(pos)
        parts.append(token)
        pos += len(token)
        if i < len(trailing_ws) and trailing_ws[i]:
            parts.append(" ")
            pos += 1

    text = "".join(parts)

    # Extract entities from BIO tags
    entities: list[Entity] = []
    current_tokens: list[str] = []
    current_type: str | None = None
    current_start: int | None = None

    for i, (token, label) in enumerate(zip(tokens, labels)):
        if label.startswith("B-"):
            # Flush previous
            if current_tokens and current_type:
                entity_text = _join_tokens(
                    current_tokens, tokens, labels, i - len(current_tokens), trailing_ws
                )
                entities.append(
                    Entity(
                        text=entity_text,
                        type=current_type,
                        start=current_start,
                        end=offsets[i - 1] + len(tokens[i - 1]) if i > 0 else 0,
                    )
                )
            bio_type = label[2:]
            current_type = LABEL_MAP.get(bio_type)
            current_tokens = [token]
            current_start = offsets[i]
        elif label.startswith("I-") and current_type:
            current_tokens.append(token)
        else:
            if current_tokens and current_type:
                entity_text = _join_tokens(
                    current_tokens, tokens, labels, i - len(current_tokens), trailing_ws
                )
                end_idx = i - 1
                entities.append(
                    Entity(
                        text=entity_text,
                        type=current_type,
                        start=current_start,
                        end=offsets[end_idx] + len(tokens[end_idx]),
                    )
                )
            current_tokens = []
            current_type = None
            current_start = None

    # Flush last entity
    if current_tokens and current_type:
        end_idx = len(tokens) - 1
        entity_text = _join_tokens(
            current_tokens, tokens, labels, len(tokens) - len(current_tokens), trailing_ws
        )
        entities.append(
            Entity(
                text=entity_text,
                type=current_type,
                start=current_start,
                end=offsets[end_idx] + len(tokens[end_idx]),
            )
        )

    return text, entities


def _join_tokens(
    entity_tokens: list[str],
    all_tokens: list[str],
    labels: list[str],
    start_idx: int,
    trailing_ws: list[bool],
) -> str:
    """Join entity tokens preserving original whitespace."""
    parts: list[str] = []
    for j, tok in enumerate(entity_tokens):
        parts.append(tok)
        idx = start_idx + j
        if j < len(entity_tokens) - 1 and idx < len(trailing_ws) and trailing_ws[idx]:
            parts.append(" ")
    return "".join(parts)


@register
class KagglePIILOAdapter(DatasetAdapter):
    name = "kaggle_piilo"
    url = "https://huggingface.co/datasets/metaboulie/Tidied-PII-Detection-Kaggle-7k"
    languages = ["en"]

    def load(
        self,
        *,
        lang: str | None = None,
        limit: int = 1000,
    ) -> Iterator[Sample]:
        from datasets import load_dataset

        if lang and lang != "en":
            return

        ds = load_dataset(
            "metaboulie/Tidied-PII-Detection-Kaggle-7k",
            split="train",
            streaming=True,
        )

        count = 0
        for ex in ds:
            if count >= limit:
                break

            tokens = ex["tokens"]
            labels = ex["labels"]
            trailing_ws = ex.get("trailing_whitespace", [True] * len(tokens))

            text, entities = _bio_to_entities(tokens, labels, trailing_ws)

            if not entities:
                continue

            count += 1
            yield Sample(text=text, lang="en", entities=entities)
