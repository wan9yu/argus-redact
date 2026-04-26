"""Adapter for wan9yu/pii-bench-zh dataset.

5,000 synthetic Chinese PII samples covering phone, id_number, bank_card,
license_plate, address, passport, email, person — with character-level offsets.
"""

from __future__ import annotations

from collections.abc import Iterator

from tests.benchmark.model import Entity, Sample

from . import register
from .base import DatasetAdapter


@register
class PIIBenchZhAdapter(DatasetAdapter):
    name = "pii_bench_zh"
    url = "https://huggingface.co/datasets/wan9yu/pii-bench-zh"
    languages = ["zh"]

    def load(
        self,
        *,
        lang: str | None = None,
        limit: int = 1000,
    ) -> Iterator[Sample]:
        from datasets import load_dataset

        if lang and lang != "zh":
            return

        ds = load_dataset(
            "wan9yu/pii-bench-zh",
            data_files="data/pii_bench_zh.jsonl",
            split="train",
            streaming=True,
        )

        count = 0
        for ex in ds:
            if count >= limit:
                break

            entities = []
            for ent in ex.get("entities", []):
                entities.append(
                    Entity(
                        text=ent["text"],
                        type=ent["type"],
                        start=ent.get("start"),
                        end=ent.get("end"),
                    )
                )

            if not entities:
                continue

            count += 1
            yield Sample(
                text=ex["text"],
                lang="zh",
                entities=entities,
            )
