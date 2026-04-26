"""Adapter for eriktks/conll2003 dataset.

Classic NER benchmark: PER, ORG, LOC, MISC. English only.
"""

from __future__ import annotations

from collections.abc import Iterator

from tests.benchmark.model import Entity, Sample

from . import register
from .base import DatasetAdapter

# IOB2 integer tags → (BIO prefix, entity type)
TAG_MAP = {
    0: ("O", None),
    1: ("B", "person"),
    2: ("I", "person"),
    3: ("B", "organization"),
    4: ("I", "organization"),
    5: ("B", "location"),
    6: ("I", "location"),
    7: ("B", "misc"),
    8: ("I", "misc"),
}


def _decode_entities(tokens: list[str], tags: list[int]) -> list[Entity]:
    """Convert IOB2 token tags to Entity list."""
    entities: list[Entity] = []
    current_tokens: list[str] = []
    current_type: str | None = None

    for token, tag_id in zip(tokens, tags):
        bio, etype = TAG_MAP.get(tag_id, ("O", None))

        if bio == "B":
            if current_tokens and current_type:
                entities.append(
                    Entity(
                        text=" ".join(current_tokens),
                        type=current_type,
                    )
                )
            current_tokens = [token]
            current_type = etype
        elif bio == "I" and etype == current_type:
            current_tokens.append(token)
        else:
            if current_tokens and current_type:
                entities.append(
                    Entity(
                        text=" ".join(current_tokens),
                        type=current_type,
                    )
                )
            current_tokens = []
            current_type = None

    if current_tokens and current_type:
        entities.append(
            Entity(
                text=" ".join(current_tokens),
                type=current_type,
            )
        )

    return entities


@register
class CoNLL2003Adapter(DatasetAdapter):
    name = "conll2003"
    url = "https://huggingface.co/datasets/eriktks/conll2003"
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
            "eriktks/conll2003",
            split="test",
            streaming=True,
            trust_remote_code=True,
        )

        count = 0
        for ex in ds:
            if count >= limit:
                break

            tokens = ex["tokens"]
            tags = ex["ner_tags"]
            entities = _decode_entities(tokens, tags)

            if not entities:
                continue

            text = " ".join(tokens)
            count += 1
            yield Sample(text=text, lang="en", entities=entities)
