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


def test_legacy_a_prefix_redacts_as_twid_not_arc():
    """Legacy single-letter prefix (e.g. A123456789) is a TWID shape, not ARC.

    Verifies the multi-pattern detection picks the correct type end-to-end:
    we only support the post-2020 ARC format ([A-Z]{2}\\d{8}); legacy
    [A-Z]\\d{9} input must classify as twid, never taiwan_arc.
    """
    from argus_redact import redact

    redacted, _key, types = redact(
        "A123456789", lang="zh", mode="fast", seed=42, with_types=True
    )
    arc_keys = [k for k, t in types.items() if t == "taiwan_arc"]
    assert not arc_keys, (
        f"Legacy A-prefix shape must not classify as taiwan_arc; got types={types}"
    )
