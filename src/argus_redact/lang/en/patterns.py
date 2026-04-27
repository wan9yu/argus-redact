"""English Layer 1 PII patterns — thin re-export of ``specs/en.py``.

The regex tuples and SSN/Luhn validators live in ``specs/en.py``; this module
exposes ``PATTERNS = build_patterns()`` for callers that import directly from
``argus_redact.lang.en.patterns``.

Legacy private validators (``_validate_ssn``, ``_validate_credit_card_luhn``,
``_MONTHS``) are re-exported for any external code that imported them by name
prior to v0.5.6.
"""

from argus_redact.specs.en import (
    _MONTHS,
    _validate_credit_card_luhn,
    _validate_ssn,
    build_patterns,
)

PATTERNS = build_patterns()

__all__ = [
    "PATTERNS",
    "_MONTHS",
    "_validate_credit_card_luhn",
    "_validate_ssn",
]
