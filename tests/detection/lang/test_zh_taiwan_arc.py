"""Taiwan ARC — new format `[A-Z]{2}\\d{8}` (post-2020)."""
import pytest
from argus_redact import redact


VALID_ARC = [
    "AB12345678",
    "AC98765432",
    "WX00000001",
]
INVALID_ARC = [
    "AB1234567",    # 7 digits
    "ABc12345678",  # lowercase 3rd char
]


@pytest.mark.parametrize("text", VALID_ARC)
def test_arc_detected(text):
    out, key = redact(text, lang="zh", mode="fast", seed=42)
    assert text not in out


@pytest.mark.parametrize("text", INVALID_ARC)
def test_invalid_arc_not_detected(text):
    out, key = redact(text, lang="zh", mode="fast", seed=42)
    assert text in out, f"Invalid ARC {text!r} unexpectedly redacted: {out}"


def test_legacy_a_prefix_consumed_by_twid_not_arc():
    """Legacy ARC shape `[A-Z]\\d{9}` collides with TWID; we only support
    the post-2020 ARC format (`[A-Z]{2}\\d{8}`). Valid TWIDs still get
    redacted (as TWID) and that's acceptable. This test documents the
    decision: ARC pattern itself does not match single-letter prefixes.
    """
    from argus_redact.lang.zh.patterns import PATTERNS
    import re

    arc_patterns = [p for p in PATTERNS if p.get("type") == "taiwan_arc"]
    assert arc_patterns, "Taiwan ARC pattern not registered"
    for p in arc_patterns:
        assert not re.fullmatch(p["pattern"], "A123456789"), (
            "ARC pattern must not match single-letter (legacy) prefix"
        )
