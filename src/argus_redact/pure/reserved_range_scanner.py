"""Single-regex scanner for reserved-range PII values.

Used by the pseudonym-llm profile to detect "polluted" input — text that
already contains realistic-redaction output. Re-redacting such input would
silently corrupt the key dict mapping.

The categorical patterns (person, address) are derived from the canonical
fake-data tables in ``specs/fakers_zh_reserved`` so that a new entry there
cannot drift out of the scanner. The numeric patterns (phone/id/bank/...)
encode the documented reserved sub-ranges directly.
"""

from __future__ import annotations

import re

from argus_redact.specs.fakers_zh_reserved import RESERVED_CITIES, RESERVED_PERSON_NAMES

# Districts used by ``fake_address_reserved`` — every reserved address starts
# with 滨海市 + one of these districts, so matching the prefix is sufficient.
_RESERVED_ADDRESS_DISTRICTS = sorted({district for _, district, _ in RESERVED_CITIES})

# Patterns for each reserved-range value type. Names are used as group labels
# and exposed via ``scan_for_pollution()`` return values.
_RESERVED_RANGE_PATTERNS = {
    "phone_zh": r"(?<!\d)19999\d{6}(?!\d)",
    "phone_landline_zh": r"(?<!\d)099-?\d{8}(?!\d)",
    "id_number_zh": r"(?<!\d)999\d{14}[\dX](?!\d)",
    "bank_card_zh": r"(?<!\d)999999\d{10}(?!\d)",
    "passport_zh": r"(?<![A-Z])[EG]99999\d{3}(?![0-9A-Z])",
    "license_plate_zh": r"[测领][A-Z]99999",
    "person_zh": "|".join(re.escape(name) for name in RESERVED_PERSON_NAMES),
    "address_zh": r"滨海市(?:" + "|".join(re.escape(d) for d in _RESERVED_ADDRESS_DISTRICTS) + r")",
}

_COMBINED = re.compile("|".join(f"(?P<{k}>{v})" for k, v in _RESERVED_RANGE_PATTERNS.items()))


def scan_for_pollution(text: str) -> list[tuple[int, int, str]]:
    """Return ``[(start, end, type_name)]`` for every reserved-range match in text."""
    return [(m.start(), m.end(), m.lastgroup) for m in _COMBINED.finditer(text)]
