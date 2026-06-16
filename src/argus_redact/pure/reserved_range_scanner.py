"""Single-regex scanner for reserved-range PII values.

Used by the pseudonym-llm profile to detect "polluted" input — text that
already contains realistic-redaction output. Re-redacting such input would
silently corrupt the key dict mapping.

The categorical patterns (person, address) are derived from the canonical
fake-data tables in ``specs/fakers_zh_reserved`` so that a new entry there
cannot drift out of the scanner. The numeric patterns (phone/id/bank/...)
encode the documented reserved sub-ranges directly.

Implementation note: ``scan_for_pollution`` is implemented in Rust
(``argus-redact-core``) and exposed via the ``_core`` extension module. This
module is a thin wrapper that preserves the original public API, including the
``_RESERVED_RANGE_PATTERNS`` dict used by architecture drift tests.
"""

from __future__ import annotations

import re

from argus_redact.specs.fakers_en_reserved import (
    RESERVED_ADDRESSES_EN,
    RESERVED_PERSON_NAMES_EN,
)
from argus_redact.specs.fakers_zh_reserved import (
    HKID_RESERVED_LETTER,
    MACAU_RESERVED_LEAD,
    RESERVED_CITIES,
    RESERVED_PERSON_NAMES,
    TWARC_RESERVED_PREFIX,
    TWID_RESERVED_LETTER,
)

# Districts used by ``fake_address_reserved`` — every reserved address starts
# with 滨海市 + one of these districts, so matching the prefix is sufficient.
_RESERVED_ADDRESS_DISTRICTS = sorted({district for _, district, _ in RESERVED_CITIES})

# Patterns for each reserved-range value type. Names are used as group labels
# and exposed via ``scan_for_pollution()`` return values.
# Also exported for use by architecture drift tests (test_realistic_drift.py,
# test_faker_in_reserved_range.py) which inspect raw pattern strings.
_RESERVED_RANGE_PATTERNS = {
    # zh
    "phone_zh": r"(?<!\d)19999\d{6}(?!\d)",
    "phone_landline_zh": r"(?<!\d)099-?\d{8}(?!\d)",
    "id_number_zh": r"(?<!\d)999\d{14}[\dX](?!\d)",
    "bank_card_zh": r"(?<!\d)999999\d{10}(?!\d)",
    "passport_zh": r"(?<![A-Z])[EG]99999\d{3}(?![0-9A-Z])",
    "hk_id_zh": rf"(?<![A-Z]){HKID_RESERVED_LETTER}\d{{6}}\((?:\d|X)\)",
    "tw_id_zh": rf"(?<![A-Za-z0-9]){TWID_RESERVED_LETTER}\d{{9}}(?!\d)",
    "macau_id_zh": rf"(?<!\d){MACAU_RESERVED_LEAD}/\d{{6}}/\d(?!\d)",
    "taiwan_arc_zh": rf"(?<![A-Za-z0-9]){TWARC_RESERVED_PREFIX}\d{{8}}(?!\d)",
    "license_plate_zh": r"[测领][A-Z]99999",
    "person_zh": "|".join(re.escape(name) for name in RESERVED_PERSON_NAMES),
    "address_zh": r"滨海市(?:" + "|".join(re.escape(d) for d in _RESERVED_ADDRESS_DISTRICTS) + r")",
    # en
    "phone_en": r"\(555\)\s*555-01\d{2}",
    "ssn_en": r"(?<!\d)999-\d{2}-\d{4}(?!\d)",
    "credit_card_en": r"(?<!\d)999999\d{10}(?!\d)",
    "person_en": "|".join(re.escape(name) for name in RESERVED_PERSON_NAMES_EN),
    "address_en": "|".join(re.escape(addr) for addr in RESERVED_ADDRESSES_EN),
    # shared (RFC documentation ranges)
    "email_shared": r"@example\.(?:com|org|net)\b",
    "ipv4_shared": r"(?<!\d)(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}(?!\d)",
    "ipv6_shared": r"\b2001:db8::[0-9a-fA-F]{1,4}\b",
    "mac_shared": r"(?<![0-9A-Fa-f:])00:00:5E:00:53:[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])",
}


def scan_for_pollution(
    text: str,
    *,
    reserved_names: dict[str, tuple[str, ...]] | None = None,
) -> list[tuple[int, int, str]]:
    """Return ``[(start, end, type_name)]`` for every reserved-range match in text.

    ``reserved_names`` overrides the canonical fake-name tables per type. Pass
    ``{"person_zh": ()}`` to disable that type entirely (useful when input may
    legitimately contain names like 张三 / John Doe that match the defaults).
    The default singleton regex is bypassed only when this argument is provided.
    """
    from argus_redact._core import scan_for_pollution as _rust_scan

    # Convert tuple values to lists for Rust (Vec<String>).
    overrides: dict[str, list[str]] | None = None
    if reserved_names is not None:
        overrides = {k: list(v) for k, v in reserved_names.items()}

    return _rust_scan(text, overrides)
