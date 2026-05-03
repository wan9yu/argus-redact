"""Internal helpers shared across reserved-range and real-prefix fakers."""

from __future__ import annotations

import random


def rand_digits(rng: random.Random, n: int) -> str:
    """Return n random ASCII digits as a string. Used by faker bodies."""
    return "".join(str(rng.randint(0, 9)) for _ in range(n))
