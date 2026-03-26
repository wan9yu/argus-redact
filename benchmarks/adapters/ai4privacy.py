"""Adapter for ai4privacy/pii-masking-300k (and 400k)."""

from __future__ import annotations

from collections.abc import Iterator

from benchmarks.model import Entity, Sample

from . import register
from .base import DatasetAdapter

# Map ai4privacy labels → argus-redact types
LABEL_MAP = {
    "EMAIL": "email",
    "TEL": "phone",
    "SOCIALNUMBER": "ssn",
    "IDCARD": "id_number",
    "PASSPORT": "passport",
    "POSTCODE": "postcode",
    "IP": "ip_address",
    "CREDITCARDNUMBER": "credit_card",
    "GIVENNAME1": "person",
    "LASTNAME1": "person",
    "LASTNAME2": "person",
    "STREET": "address",
    "CITY": "location",
    "STATE": "location",
}

# ai4privacy language code → argus-redact language code
LANG_MAP = {
    "English": "en",
    "German": "de",
    "French": "fr",
    "Italian": "it",
    "Spanish": "es",
    "Dutch": "nl",
}


@register
class Ai4PrivacyAdapter(DatasetAdapter):
    name = "ai4privacy"
    url = "https://huggingface.co/datasets/ai4privacy/pii-masking-300k"
    languages = ["en", "de", "fr", "it", "es", "nl"]

    def load(
        self,
        *,
        lang: str | None = None,
        limit: int = 1000,
    ) -> Iterator[Sample]:
        from datasets import load_dataset

        ds = load_dataset(
            "ai4privacy/pii-masking-300k",
            split="train",
            streaming=True,
        )

        count = 0
        for ex in ds:
            if count >= limit:
                break

            # Detect language from the example
            sample_lang = LANG_MAP.get(ex.get("language", ""), "en")
            if lang and sample_lang != lang:
                continue

            entities = []
            for span in ex.get("privacy_mask", []):
                label = span.get("label", "")
                if label in LABEL_MAP:
                    entities.append(Entity(
                        text=span["value"],
                        type=LABEL_MAP[label],
                    ))

            if not entities:
                continue

            count += 1
            yield Sample(
                text=ex["source_text"],
                lang=sample_lang,
                entities=entities,
            )
