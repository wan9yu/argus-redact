"""An invisible character inserted mid-token must not defeat detection.

`is_invisible` was a hand-enumerated carrier list rather than Unicode's
`Default_Ignorable_Code_Point` property. Fourteen ignorable ranges were absent,
so one of them dropped inside a phone / email / ID split the token in the
normalized view and the Layer-1 regex failed OPEN — the PII was emitted
verbatim.

The second half of this file is the neighbour-integrity net: stripping a
carrier changes the offset map, and the map is what maps a detected span back
to the original text. Any future offset-map change has to keep surrounding
non-PII text byte-identical, so it is brute-forced here rather than argued.
"""

from __future__ import annotations

import pytest

from argus_redact import redact

# One representative code point per range the hand-written predicate missed.
NEWLY_COVERED = [
    0x034F,  # COMBINING GRAPHEME JOINER
    0x061C,  # ARABIC LETTER MARK
    0x115F,  # HANGUL CHOSEONG FILLER
    0x1160,  # HANGUL JUNGSEONG FILLER
    0x17B4,  # KHMER VOWEL INHERENT AQ
    0x17B5,  # KHMER VOWEL INHERENT AA
    0x180B,  # MONGOLIAN FREE VARIATION SELECTOR ONE
    0x180E,  # MONGOLIAN VOWEL SEPARATOR
    0x180F,  # MONGOLIAN FREE VARIATION SELECTOR FOUR
    0x2065,  # reserved, Default_Ignorable
    0x206A,  # INHIBIT SYMMETRIC SWAPPING
    0x206F,  # NOMINAL DIGIT SHAPES
    0x3164,  # HANGUL FILLER
    0xFFA0,  # HALFWIDTH HANGUL FILLER
    0xFFF0,  # reserved, Default_Ignorable
    0xFFF8,  # reserved, Default_Ignorable
    0x1BCA0,  # SHORTHAND FORMAT LETTER OVERLAP
    0x1D173,  # MUSICAL SYMBOL BEGIN BEAM
    0xE0080,  # reserved in the Tags block
    0xE01F0,  # reserved past the ideographic variation selectors
    0xE0FFF,  # last Default_Ignorable code point
]

# Already covered before v0.8.9 — pinned so a range edit cannot silently drop one.
ALREADY_COVERED = [0x200B, 0x200D, 0x00AD, 0xFEFF, 0x202E, 0x2060, 0xFE0F, 0xE0001]


@pytest.mark.parametrize("cp", NEWLY_COVERED + ALREADY_COVERED, ids=lambda cp: f"U+{cp:04X}")
@pytest.mark.parametrize(
    "template, secret",
    [
        ("联系电话 {}", "13800138000"),
        ("邮箱 {}", "zhangsan@example.com"),
        ("身份证 {}", "440524188001010014"),
    ],
    ids=["phone", "email", "id"],
)
def test_ignorable_carrier_does_not_hide_pii(cp, template, secret):
    carrier = chr(cp)
    # Split the secret in the middle — the position an attacker would pick.
    half = len(secret) // 2
    smuggled = secret[:half] + carrier + secret[half:]

    redacted, key = redact(template.format(smuggled), lang="zh", mode="fast")

    assert key, f"U+{cp:04X} defeated detection entirely"
    assert secret[:half] not in redacted or secret[half:] not in redacted, (
        f"U+{cp:04X}: the secret survived into the output: {redacted!r}"
    )


# Benign neighbours: real text in several scripts, none of it PII, none of it
# affected by the confusable/NFKC folds that run after the invisible strip.
NEIGHBOURS = ["前面", "hello", "안녕", "こんにちは", "Ω", "— ", "0", " "]


@pytest.mark.parametrize("cp", NEWLY_COVERED, ids=lambda cp: f"U+{cp:04X}")
def test_neighbour_integrity_surrounding_text_is_byte_identical(cp):
    """Brute-force: with no PII present, redaction must be the identity
    function no matter which ignorable carrier sits between the neighbours."""
    carrier = chr(cp)
    for left in NEIGHBOURS:
        for right in NEIGHBOURS:
            source = f"{left}{carrier}{right}"
            redacted, key = redact(source, lang="zh", mode="fast")
            assert key == {}, f"U+{cp:04X}: false detection in {source!r} -> {key}"
            assert redacted == source, (
                f"U+{cp:04X}: non-PII text mutated: {source!r} -> {redacted!r}"
            )


@pytest.mark.parametrize("cp", NEWLY_COVERED, ids=lambda cp: f"U+{cp:04X}")
def test_neighbour_integrity_text_around_a_redacted_span_survives(cp):
    """With PII present, everything OUTSIDE the replaced span must survive
    byte-for-byte, carrier included — the carrier is only dropped from the
    detection-side view, never from the output."""
    carrier = chr(cp)
    prefix = f"备注{carrier}见下"
    suffix = f"结束{carrier}。"
    source = f"{prefix} 13800138000 {suffix}"

    redacted, key = redact(source, lang="zh", mode="fast")

    assert key, f"U+{cp:04X}: the phone was not detected"
    assert redacted.startswith(prefix), f"prefix mutated: {redacted!r}"
    assert redacted.endswith(suffix), f"suffix mutated: {redacted!r}"
