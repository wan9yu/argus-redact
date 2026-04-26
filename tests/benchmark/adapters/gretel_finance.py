"""Adapter for gretelai/synthetic_pii_finance_multilingual dataset.

56K records across 6 languages, financial document context.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from tests.benchmark.model import Entity, Sample

from . import register
from .base import DatasetAdapter

# Map Gretel labels → argus-redact types
LABEL_MAP = {
    "name": "person",
    "email": "email",
    "phone_number": "phone",
    "street_address": "address",
    "city": "location",
    "state": "location",
    "zip_code": "postcode",
    "country": "location",
    "company": "organization",
    "credit_card_number": "credit_card",
    "iban": "iban",
    "ssn": "ssn",
    "tax_id": "tax_id",
}

LANG_MAP = {
    "English": "en",
    "German": "de",
    "French": "fr",
    "Italian": "it",
    "Spanish": "es",
    "Dutch": "nl",
    "Swedish": "sv",
}


@register
class GretelFinanceAdapter(DatasetAdapter):
    name = "gretel_finance"
    url = "https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual"
    languages = ["en", "de", "fr", "it", "es", "nl", "sv"]

    def load(
        self,
        *,
        lang: str | None = None,
        limit: int = 1000,
    ) -> Iterator[Sample]:
        from datasets import load_dataset

        ds = load_dataset(
            "gretelai/synthetic_pii_finance_multilingual",
            split="train",
            streaming=True,
        )

        count = 0
        for ex in ds:
            if count >= limit:
                break

            sample_lang = LANG_MAP.get(ex.get("language", ""), "en")
            if lang and sample_lang != lang:
                continue

            text = ex["generated_text"]

            spans_raw = ex.get("pii_spans", "[]")
            try:
                spans = json.loads(spans_raw) if isinstance(spans_raw, str) else spans_raw
            except (json.JSONDecodeError, TypeError):
                continue

            entities = []
            for span in spans:
                label = span.get("label", "")
                if label in LABEL_MAP:
                    start = span["start"]
                    end = span["end"]
                    entities.append(
                        Entity(
                            text=text[start:end],
                            type=LABEL_MAP[label],
                            start=start,
                            end=end,
                        )
                    )

            if not entities:
                continue

            count += 1
            yield Sample(text=text, lang=sample_lang, entities=entities)
