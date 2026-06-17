"""Parity test: _core.reserved_range_patterns() must match the canonical set.

This is the bit-identity gate for the reserved-range pattern list — the Rust
SSOT is ``_core.reserved_range_patterns()``. The Python ``_RESERVED_RANGE_PATTERNS``
dict has been deleted; this test locks the Rust output against the frozen
canonical snapshot captured from the original Python dict (modulo harmless
cosmetic differences: Python 3.11 ``re.escape`` unnecessarily escapes spaces;
``fancy_regex::escape`` does not — both patterns match the same strings).
"""
import argus_redact._core as _core


def test_core_reserved_range_patterns_match_python_dict():
    # Canonical snapshot — derived from the original Python dict.
    # Note: spaces in person_en / address_en are NOT backslash-escaped here;
    # Python 3.11 re.escape() over-escapes spaces ("\\ ") while fancy_regex::escape
    # correctly omits the backslash. The patterns are functionally identical.
    EXPECTED = {
        "address_en": "1313 Mockingbird Lane, Springfield, USA|742 Evergreen Terrace, Springfield, USA|221B Baker Street, London, UK|12 Grimmauld Place, London, UK|1630 Revello Drive, Sunnydale, USA|31 Spooner Street, Quahog, USA",
        "address_zh": "滨海市(?:东江区|北原区|西陆区)",
        "bank_card_zh": r"(?<!\d)999999\d{10}(?!\d)",
        "credit_card_en": r"(?<!\d)999999\d{10}(?!\d)",
        "email_shared": r"@example\.(?:com|org|net)\b",
        "hk_id_zh": r"(?<![A-Z])Z\d{6}\((?:\d|X)\)",
        "id_number_zh": r"(?<!\d)999\d{14}[\dX](?!\d)",
        "ipv4_shared": r"(?<!\d)(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}(?!\d)",
        "ipv6_shared": r"\b2001:db8::[0-9a-fA-F]{1,4}\b",
        "license_plate_zh": "[测领][A-Z]99999",
        "mac_shared": r"(?<![0-9A-Fa-f:])00:00:5E:00:53:[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])",
        "macau_id_zh": r"(?<!\d)9/\d{6}/\d(?!\d)",
        "passport_zh": r"(?<![A-Z])[EG]99999\d{3}(?![0-9A-Z])",
        "person_en": r"John Doe|Jane Doe|Jane Roe|John Roe|Richard Roe|Mary Roe|John Q\. Public|Alice Liddell|Pat Roe|Sandy Doe",
        "person_zh": "张三|李四|王五|赵六|钱七|焦大|茗烟|傻大姐|彩云|佩凤|偕鸳|卷帘|毕马温",
        "phone_en": r"\(555\)\s*555-01\d{2}",
        "phone_landline_zh": r"(?<!\d)099-?\d{8}(?!\d)",
        "phone_zh": r"(?<!\d)19999\d{6}(?!\d)",
        "ssn_en": r"(?<!\d)999-\d{2}-\d{4}(?!\d)",
        "taiwan_arc_zh": r"(?<![A-Za-z0-9])WW\d{8}(?!\d)",
        "tw_id_zh": r"(?<![A-Za-z0-9])W\d{9}(?!\d)",
    }
    got = dict(_core.reserved_range_patterns())
    assert got == EXPECTED
