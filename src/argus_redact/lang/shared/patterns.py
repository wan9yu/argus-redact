"""Cross-language Layer-1 helpers: faker-shared checksum utilities. Both the
regex pattern DATA and its validation run in the Rust core; ``PATTERNS`` below
is a thin reader of that SSOT, and the per-type validators (jwt, etc.) live in
``argus-redact-core/src/validators.rs``."""


def luhn_check_digit(body: str) -> int:
    """Compute the Luhn check digit for a numeric body (digit appended at end)."""
    digits = [int(d) for d in body]
    doubled = digits[-1::-2]
    not_doubled = digits[-2::-2]
    doubled_sum = sum(d * 2 - 9 if d * 2 > 9 else d * 2 for d in doubled)
    return (10 - (doubled_sum + sum(not_doubled)) % 10) % 10


def validate_luhn(value: str) -> bool:
    """Luhn checksum — shared by all languages' bank/credit card validation."""
    digits = "".join(d for d in value if d.isdigit())
    # 13 is the minimum plausible card length; callers needing a stricter floor
    # (e.g. CN bank ≥16) guard separately.
    if len(digits) < 13:
        return False
    return luhn_check_digit(digits[:-1]) == int(digits[-1])


# Pattern DATA is the SSOT in the Rust core (RON); read it here. Validation for
# each type (jwt, etc.) also runs in the Rust core (validators.rs) — there is no
# Python validate callback.
from argus_redact.lang._loader import core_patterns  # noqa: E402

PATTERNS = core_patterns("shared")
