"""Pseudonym code generation with seed support."""

from __future__ import annotations

import random
import secrets


def max_pseudonym_length(config: dict | None = None) -> int:
    """Return the maximum possible pseudonym length based on config.

    Default format: PREFIX-NNNNN (prefix + dash + 5 digits).
    Useful for streaming buffer sizing.
    """
    from argus_redact.pure.replacer import DEFAULT_PREFIXES
    prefixes = set(DEFAULT_PREFIXES.values())
    if config:
        for type_config in config.values():
            if isinstance(type_config, dict) and "prefix" in type_config:
                prefixes.add(type_config["prefix"])
    if not prefixes:
        return 7  # "P-00000"
    longest_prefix = max(len(p) for p in prefixes)
    return longest_prefix + 1 + 5  # prefix + "-" + 5 digits


def generate_pseudonym(
    *,
    prefix: str = "P",
    code_range: tuple[int, int] = (1, 99999),
    seed: int | None = None,
) -> str:
    """Generate a single pseudonym code like P-037."""
    lo, hi = code_range
    if seed is not None:
        rng = random.Random(seed)
        num = rng.randint(lo, hi)
    else:
        num = secrets.randbelow(hi - lo + 1) + lo
    return f"{prefix}-{num:05d}"


try:
    from argus_redact._core import PseudonymGenerator
except ImportError:

    class PseudonymGenerator:
        """Stateful generator (Python fallback)."""

        def __init__(
            self,
            *,
            prefix: str = "P",
            code_range: tuple[int, int] = (1, 99999),
            seed: int | None = None,
            existing_key: dict[str, str] | None = None,
        ):
            self._prefix = prefix
            self._code_range = code_range
            self._rng = random.Random(seed) if seed is not None else None
            self._entity_to_code: dict[str, str] = {}
            self._used_codes: set[str] = set()

            if existing_key:
                for code, entity in existing_key.items():
                    if code.startswith(f"{prefix}-"):
                        self._entity_to_code[entity] = code
                        self._used_codes.add(code)

        def get(self, entity: str) -> str:
            if entity in self._entity_to_code:
                return self._entity_to_code[entity]
            code = self._generate_unique()
            self._entity_to_code[entity] = code
            self._used_codes.add(code)
            return code

        def _generate_unique(self) -> str:
            lo, hi = self._code_range
            for _ in range(1000):
                if self._rng is not None:
                    num = self._rng.randint(lo, hi)
                else:
                    num = secrets.randbelow(hi - lo + 1) + lo
                code = f"{self._prefix}-{num:05d}"
                if code not in self._used_codes:
                    return code
            self._code_range = (lo, hi * 10)
            return self._generate_unique()
