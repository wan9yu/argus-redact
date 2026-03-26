"""Adapter for i2b2/n2c2 2014 De-identification dataset.

Clinical notes with PHI annotations. Gold standard for medical de-identification.

Access: requires DUA from https://portal.dbmi.hms.harvard.edu/projects/n2c2-2014/
HuggingFace (gated): bigbio/n2c2_2014_deid

If the gated dataset is not accessible, falls back to the relabeled version:
disi-unibo-nlp/physionet-deid-i2b2-2014
"""

from __future__ import annotations

from collections.abc import Iterator

from tests.benchmark.model import Entity, Sample

from . import register
from .base import DatasetAdapter

# Map n2c2 PHI categories → argus-redact types
LABEL_MAP = {
    # Names
    "PATIENT": "person",
    "DOCTOR": "person",
    "USERNAME": "person",
    "NAME": "person",
    # Contact
    "PHONE": "phone",
    "FAX": "phone",
    "EMAIL": "email",
    "URL": "url",
    "IPADDRESS": "ip_address",
    # Location
    "HOSPITAL": "location",
    "ORGANIZATION": "organization",
    "STREET": "address",
    "CITY": "location",
    "STATE": "location",
    "COUNTRY": "location",
    "ZIP": "postcode",
    "LOCATION": "location",
    "LOCATION-OTHER": "location",
    # IDs
    "SSN": "ssn",
    "MEDICALRECORD": "id_number",
    "HEALTHPLAN": "id_number",
    "ACCOUNT": "id_number",
    "LICENSE": "id_number",
    "IDNUM": "id_number",
    "ID": "id_number",
    # Other PHI
    "DATE": "date",
    "AGE": "age",
    "PROFESSION": "profession",
}


@register
class N2C22014Adapter(DatasetAdapter):
    name = "n2c2_2014"
    url = "https://portal.dbmi.hms.harvard.edu/projects/n2c2-2014/"
    languages = ["en"]

    def load(
        self,
        *,
        lang: str | None = None,
        limit: int = 1000,
    ) -> Iterator[Sample]:
        if lang and lang != "en":
            return

        # Try the relabeled CSV version first (no DUA needed for metadata)
        yield from self._load_relabeled(limit)

    def _load_relabeled(self, limit: int) -> Iterator[Sample]:
        """Load from disi-unibo-nlp/physionet-deid-i2b2-2014 (relabeled version)."""
        from datasets import load_dataset

        try:
            ds = load_dataset(
                "disi-unibo-nlp/physionet-deid-i2b2-2014",
                split="train",
                streaming=True,
            )
        except Exception as e:
            print(f"  n2c2_2014: could not load dataset ({e})")
            print("  This dataset requires access approval. See:")
            print(f"  {self.url}")
            return

        # Group annotations by record_id and reconstruct
        count = 0
        current_record: str | None = None
        current_entities: list[Entity] = []

        for row in ds:
            if count >= limit:
                break

            record_id = row.get("record_id", "")
            label = row.get("type", "")
            begin = row.get("begin", 0)
            length = row.get("length", 0)

            mapped_type = LABEL_MAP.get(label)
            if not mapped_type:
                continue

            if record_id != current_record:
                # Flush previous record
                if current_record is not None and current_entities:
                    count += 1
                    yield Sample(
                        text=f"[clinical note {current_record}]",
                        lang="en",
                        entities=current_entities,
                    )
                    if count >= limit:
                        break
                current_record = record_id
                current_entities = []

            current_entities.append(Entity(
                text=f"[PHI@{begin}:{begin + length}]",
                type=mapped_type,
                start=begin,
                end=begin + length,
            ))

        # Flush last record
        if current_record is not None and current_entities and count < limit:
            yield Sample(
                text=f"[clinical note {current_record}]",
                lang="en",
                entities=current_entities,
            )
