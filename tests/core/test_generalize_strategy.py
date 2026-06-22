"""Golden tests for the lossy `generalize` location-coarsening strategy.

`generalize` maps a detected location/address span to its city (default) or
province ancestor via the GB/T 2260 gazetteer in the Rust core. It is LOSSY: the
coarse value (杭州市) maps back to many originals, so the strategy emits NO
restore-key entry — round-tripping a generalized text must not mis-restore an
unrelated city mention. These tests assert both the coarsening output and the
absence of a key entry, driving the full redact() path (fast-mode detection +
core replace), which detects the Chinese address in this fixture.

The Rust core has its own detection-independent golden in
`crates/argus-redact-core/src/replace.rs` (feeds the entity straight into
`replace()`); this file locks the Python end-to-end behavior.
"""

from argus_redact import redact

# A sentence whose address span (杭州西湖区文一路100号) is detected in fast mode.
_TEXT = "他住在杭州西湖区文一路100号。"


def test_generalize_address_to_city_is_lossy():
    out, key = redact(
        _TEXT,
        mode="fast",
        lang=["zh"],
        salt=42,
        config={
            "address": {"strategy": "generalize"},
            "location": {"strategy": "generalize"},
        },
    )
    # City is the default coarsening level: district/street → city ancestor.
    assert "杭州市" in out
    assert "文一路100号" not in out
    # Lossy: no restore-key entry for the coarse value.
    assert "杭州市" not in key
    assert key == {}


def test_generalize_address_to_province_is_lossy():
    out, key = redact(
        _TEXT,
        mode="fast",
        lang=["zh"],
        salt=42,
        config={
            "address": {"strategy": "generalize", "level": "province"},
            "location": {"strategy": "generalize", "level": "province"},
        },
    )
    assert "浙江省" in out
    assert "文一路100号" not in out
    assert "浙江省" not in key
    assert key == {}
