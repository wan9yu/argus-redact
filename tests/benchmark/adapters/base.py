"""Base class for dataset adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from tests.benchmark.model import Sample


class DatasetAdapter(ABC):
    """Adapter that loads a public dataset and yields normalized Samples."""

    name: str  # e.g. "ai4privacy"
    url: str  # dataset source URL
    languages: list[str]  # supported languages

    @abstractmethod
    def load(
        self,
        *,
        lang: str | None = None,
        limit: int = 1000,
    ) -> Iterator[Sample]:
        """Download (if needed) and yield labeled samples.

        Args:
            lang: Filter by language. None = all languages.
            limit: Max number of samples to yield.
        """
