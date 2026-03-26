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
from . import conll2003 as _conll2003  # noqa: E402, F401
from . import gretel_finance as _gretel_finance  # noqa: E402, F401
from . import kaggle_piilo as _kaggle_piilo  # noqa: E402, F401
from . import n2c2_2014 as _n2c2_2014  # noqa: E402, F401
from . import nemotron as _nemotron  # noqa: E402, F401
from . import pii_bench_zh as _pii_bench_zh  # noqa: E402, F401
from . import pii_bench_zh_chat as _pii_bench_zh_chat  # noqa: E402, F401
from . import wikiann as _wikiann  # noqa: E402, F401
