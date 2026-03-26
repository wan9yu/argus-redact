"""Adapter for nvidia/Nemotron-PII dataset.

100K English records, 55+ PII types, character-level span annotations.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from tests.benchmark.model import Entity, Sample

from . import register
from .base import DatasetAdapter

# Map Nemotron labels → argus-redact types
LABEL_MAP = {
    # Names
    "first_name": "person",
    "last_name": "person",
    "full_name": "person",
    "username": "person",
    # Contact
    "email": "email",
    "phone_number": "phone",
    # IDs
    "ssn": "ssn",
    "drivers_license": "id_number",
    "passport_number": "passport",
    "national_id": "id_number",
    "tax_id": "tax_id",
    # Financial
    "credit_card_number": "credit_card",
    "bank_account_number": "bank_card",
    "iban": "iban",
    # Address
    "street_address": "address",
    "city": "location",
    "state": "location",
    "zip_code": "postcode",
    "country": "location",
    # Medical / PHI
    "date_of_birth": "date",
    "medical_record_number": "id_number",
    "health_insurance_id": "id_number",
}


@register
class NemotronAdapter(DatasetAdapter):
    name = "nemotron"
    url = "https://huggingface.co/datasets/nvidia/Nemotron-PII"
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
            "nvidia/Nemotron-PII",
            split="train",
            streaming=True,
        )

        count = 0
        for ex in ds:
            if count >= limit:
                break

            spans_raw = ex.get("spans", "[]")
            try:
                spans = json.loads(spans_raw) if isinstance(spans_raw, str) else spans_raw
            except (json.JSONDecodeError, TypeError):
                continue

            text = ex["text"]
            entities = []
            for span in spans:
                label = span.get("label", "")
                if label in LABEL_MAP:
                    entities.append(Entity(
                        text=span.get("text", text[span["start"]:span["end"]]),
                        type=LABEL_MAP[label],
                        start=span.get("start"),
                        end=span.get("end"),
                    ))

            if not entities:
                continue

            count += 1
            yield Sample(text=text, lang="en", entities=entities)
