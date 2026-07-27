"""Internal helper shared by the benchmark corpus fakers in this package.

Test-side only: production fake generation lives in the Rust core, not here.
"""

from __future__ import annotations

import random


def rand_digits(rng: random.Random, n: int) -> str:
    """Return n random ASCII digits as a string. Used by faker bodies."""
    return "".join(str(rng.randint(0, 9)) for _ in range(n))
