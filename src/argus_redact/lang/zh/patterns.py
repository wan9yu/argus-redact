"""Chinese regex patterns for Layer 1 PII detection.

Person name detection is handled separately by person.py (candidate + scoring).
This module only contains structural PII patterns (phone, ID, bank card, etc.).
"""

# Kept for fixture generation only (tests/benchmark/generators/fakers_zh_real.py);
# runtime validation lives in Rust validators.rs.
GB11643_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
GB11643_CHECK_CHARS = "10X98765432"


def gb11643_check_char(body17: str) -> str:
    """Compute GB 11643 check character for a 17-digit ID body."""
    total = sum(int(body17[i]) * GB11643_WEIGHTS[i] for i in range(17))
    return GB11643_CHECK_CHARS[total % 11]


# GB 32100-2015 Unified Social Credit Code constants
_CREDIT_CODE_CHARSET = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_CREDIT_CODE_CHAR_TO_VAL = {c: i for i, c in enumerate(_CREDIT_CODE_CHARSET)}
_CREDIT_CODE_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)


# Pattern DATA is the SSOT in the Rust core (RON); read it here. Validation for
# each type (organization, school, etc.) also runs in the Rust core
# (validators.rs) — there is no Python validate callback.
from argus_redact.lang._loader import core_patterns  # noqa: E402

PATTERNS = core_patterns("zh")
