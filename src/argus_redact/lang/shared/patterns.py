"""Cross-language Layer-1 helpers: faker-shared checksum utilities and the
``jwt`` deferred validator. The regex pattern DATA itself lives in the Rust
core (RON); ``PATTERNS`` below is a thin reader of that SSOT."""

import base64
import json


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
    if len(digits) < 16:
        return False
    return luhn_check_digit(digits[:-1]) == int(digits[-1])


def _validate_jwt(value: str) -> bool:
    """JWT format validation: 3 base64url segments; header decodes to JSON with 'alg' field."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    try:
        header_b64 = parts[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
        return isinstance(header, dict) and "alg" in header
    except (ValueError, UnicodeDecodeError):
        return False


# Pattern DATA is the SSOT in the Rust core (RON); read it here. The deferred
# `jwt` validator (above) is re-attached by core_patterns as a `validate` callable.
from argus_redact.lang._loader import core_patterns

PATTERNS = core_patterns("shared")
