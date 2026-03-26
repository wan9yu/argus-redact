"""Dataset adapter registry."""

from __future__ import annotations

from .base import DatasetAdapter

REGISTRY: dict[str, type[DatasetAdapter]] = {}


def register(cls: type[DatasetAdapter]) -> type[DatasetAdapter]:
    """Class decorator — register an adapter by its name."""
    REGISTRY[cls.name] = cls
    return cls


def get_adapter(name: str) -> DatasetAdapter:
    """Instantiate an adapter by name."""
    if name not in REGISTRY:
        available = ", ".join(sorted(REGISTRY)) or "(none)"
        raise ValueError(f"Unknown dataset '{name}'. Available: {available}")
    return REGISTRY[name]()


def list_adapters() -> list[str]:
    return sorted(REGISTRY)


# Import adapters so they self-register
from . import ai4privacy as _ai4privacy  # noqa: E402, F401
