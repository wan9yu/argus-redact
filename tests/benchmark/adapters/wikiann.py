"""Adapter for unimelb-nlp/wikiann (PAN-X) dataset.

Multilingual NER: PER, ORG, LOC across 282 languages.
Useful for evaluating name/location/org detection.
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
}

# Languages argus-redact supports that WikiANN also covers
SUPPORTED_LANGS = ["zh", "en", "ja", "ko", "de", "uk"]


def _decode_entities(tokens: list[str], tags: list[int], lang: str) -> list[Entity]:
    """Convert IOB2 token tags to Entity list."""
    entities: list[Entity] = []
    current_tokens: list[str] = []
    current_type: str | None = None

    for token, tag_id in zip(tokens, tags):
        bio, etype = TAG_MAP.get(tag_id, ("O", None))

        if bio == "B":
            # Flush previous entity
            if current_tokens and current_type:
                text = "" if lang in ("zh", "ja") else " "
                entities.append(
                    Entity(
                        text=text.join(current_tokens),
                        type=current_type,
                    )
                )
            current_tokens = [token]
            current_type = etype
        elif bio == "I" and etype == current_type:
            current_tokens.append(token)
        else:
            # Flush previous entity
            if current_tokens and current_type:
                text = "" if lang in ("zh", "ja") else " "
                entities.append(
                    Entity(
                        text=text.join(current_tokens),
                        type=current_type,
                    )
                )
            current_tokens = []
            current_type = None

    # Flush last entity
    if current_tokens and current_type:
        text = "" if lang in ("zh", "ja") else " "
        entities.append(
            Entity(
                text=text.join(current_tokens),
                type=current_type,
            )
        )

    return entities


@register
class WikiANNAdapter(DatasetAdapter):
    name = "wikiann"
    url = "https://huggingface.co/datasets/unimelb-nlp/wikiann"
    languages = SUPPORTED_LANGS

    def load(
        self,
        *,
        lang: str | None = None,
        limit: int = 1000,
    ) -> Iterator[Sample]:
        from datasets import load_dataset

        langs = [lang] if lang else SUPPORTED_LANGS
        per_lang_limit = limit // len(langs)

        for lng in langs:
            if lng not in SUPPORTED_LANGS:
                continue

            ds = load_dataset(
                "unimelb-nlp/wikiann",
                lng,
                split="test",
                streaming=True,
            )

            count = 0
            for ex in ds:
                if count >= per_lang_limit:
                    break

                tokens = ex["tokens"]
                tags = ex["ner_tags"]
                entities = _decode_entities(tokens, tags, lng)

                if not entities:
                    continue

                # Reconstruct text
                joiner = "" if lng in ("zh", "ja") else " "
                text = joiner.join(tokens)

                count += 1
                yield Sample(text=text, lang=lng, entities=entities)
