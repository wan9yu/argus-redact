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

import functools
import re

from argus_redact.specs.fakers_en_reserved import (
    RESERVED_ADDRESSES_EN,
    RESERVED_PERSON_NAMES_EN,
)
from argus_redact.specs.fakers_zh_reserved import RESERVED_CITIES, RESERVED_PERSON_NAMES

# Districts used by ``fake_address_reserved`` — every reserved address starts
# with 滨海市 + one of these districts, so matching the prefix is sufficient.
_RESERVED_ADDRESS_DISTRICTS = sorted({district for _, district, _ in RESERVED_CITIES})

# Patterns for each reserved-range value type. Names are used as group labels
# and exposed via ``scan_for_pollution()`` return values.
_RESERVED_RANGE_PATTERNS = {
    # zh
    "phone_zh": r"(?<!\d)19999\d{6}(?!\d)",
    "phone_landline_zh": r"(?<!\d)099-?\d{8}(?!\d)",
    "id_number_zh": r"(?<!\d)999\d{14}[\dX](?!\d)",
    "bank_card_zh": r"(?<!\d)999999\d{10}(?!\d)",
    "passport_zh": r"(?<![A-Z])[EG]99999\d{3}(?![0-9A-Z])",
    "hk_id_zh": r"(?<![A-Z])Z\d{6}\((?:\d|X)\)",
    "tw_id_zh": r"(?<![A-Za-z0-9])W\d{9}(?!\d)",
    "macau_id_zh": r"(?<!\d)9/\d{6}/\d(?!\d)",
    "taiwan_arc_zh": r"(?<![A-Za-z0-9])WW\d{8}(?!\d)",
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

_COMBINED = re.compile("|".join(f"(?P<{k}>{v})" for k, v in _RESERVED_RANGE_PATTERNS.items()))


@functools.lru_cache(maxsize=32)
def _build_combined_with_overrides(overrides: tuple[tuple[str, tuple[str, ...]], ...]) -> re.Pattern:
    """Build the combined regex with per-type overrides; cached on hashable input.

    Empty tuple for a type means "drop that type entirely from the alternation".
    """
    overrides_dict = dict(overrides)
    patterns = {}
    for type_name, default_pattern in _RESERVED_RANGE_PATTERNS.items():
        if type_name in overrides_dict:
            names = overrides_dict[type_name]
            if not names:
                continue  # disabled — drop from alternation
            patterns[type_name] = "|".join(re.escape(n) for n in names)
        else:
            patterns[type_name] = default_pattern
    return re.compile("|".join(f"(?P<{k}>{v})" for k, v in patterns.items()))


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
    if reserved_names is None:
        return [(m.start(), m.end(), m.lastgroup) for m in _COMBINED.finditer(text)]
    # Convert to hashable form; cache per unique override shape.
    overrides = tuple(sorted((k, tuple(v)) for k, v in reserved_names.items()))
    combined = _build_combined_with_overrides(overrides)
    return [(m.start(), m.end(), m.lastgroup) for m in combined.finditer(text)]
