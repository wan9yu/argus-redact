"""Pseudonym code generation with seed support."""

import random
import secrets


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


class PseudonymGenerator:
    """Stateful generator that tracks used codes and entity-to-code mappings.

    Same entity always gets the same code within one generator instance.
    Codes never collide with each other or with existing key entries.
    """

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
        if seed is not None:
            self._rng = random.Random(seed)
        else:
            self._rng = None

        # entity text -> pseudonym code
        self._entity_to_code: dict[str, str] = {}
        # all used codes (for collision checking)
        self._used_codes: set[str] = set()

        if existing_key:
            for code, entity in existing_key.items():
                if code.startswith(f"{prefix}-"):
                    self._entity_to_code[entity] = code
                    self._used_codes.add(code)

    def get(self, entity: str) -> str:
        """Get or create a pseudonym code for the given entity text."""
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
        # Auto-expand range and retry
        self._code_range = (lo, hi * 10)
        return self._generate_unique()
