# tests/security/test_exotic_digit_recall.py
"""Non-ASCII decimal-digit (Nd) bypass — Arabic-Indic ١, Devanagari १, … .

A non-ASCII Unicode decimal digit is Unicode-`\\d` but not `is_ascii_digit`, which
defeats PII detection in TWO opposite ways:

* BOUNDARY: an exotic digit ADJACENT to an ASCII PII run makes the pattern's
  `(?<![0-9])` / `(?![0-9])` boundary lookaround (pre-fix: `\\d`) see a digit and
  refuse the match.
* INTERIOR: an exotic digit INSIDE a checksum ID passes the `\\d{N}` body but the
  `is_ascii_digit` validator fails → confidence 0.3 near-miss → never redacted.

The fix ASCII-scopes the boundary anchors and folds an interior exotic digit
(flanked by ASCII digits on both sides) to ASCII. Both must close while the
CJK-homograph protection and every clean case stay exactly as before.
"""

import pytest

from argus_redact import redact

# Arabic-Indic (U+0660-0669) and Devanagari (U+0966-096F).
AR = {str(d): chr(0x0660 + d) for d in range(10)}  # AR["1"] == "١"
DV = {str(d): chr(0x0966 + d) for d in range(10)}  # DV["1"] == "१"

PHONE = "13800138000"  # zh mobile
ID = "110101199003070468"  # zh 18-digit national ID (valid GB11643 checksum)
PAN = "4111111111111111"  # Visa test PAN (valid Luhn)


def _redact(text, lang):
    return redact(text, lang=lang, mode="fast", salt=42)


# ── Arm (b): BOUNDARY exotic digit no longer suppresses the adjacent ASCII PII ──
@pytest.mark.parametrize(
    "text,lang,secret",
    [
        (f"电话{AR['1']}{PHONE}", "zh", PHONE),  # leading Arabic-Indic
        (f"电话{PHONE}{AR['9']}", "zh", PHONE),  # trailing Arabic-Indic
        (f"电话{DV['1']}{PHONE}", "zh", PHONE),  # leading Devanagari
        (f"card {AR['1']}{PAN}", "en", PAN),  # PAN preceded by Arabic-Indic
    ],
)
def test_boundary_exotic_digit_does_not_defeat_detection(text, lang, secret):
    out, key = _redact(text, lang)
    assert len(key) >= 1, f"no entity detected — boundary leak: {text!r} -> {out!r}"
    assert secret not in out, f"PII leaked verbatim: {text!r} -> {out!r}"


# ── Arm (a): INTERIOR exotic digit folds so the checksum validator sees ASCII ──
@pytest.mark.parametrize(
    "text",
    [
        f"公民身份号码11010{AR['1']}199003070468",  # Arabic-Indic interior
        f"公民身份号码11010{DV['1']}199003070468",  # Devanagari interior
    ],
)
def test_interior_exotic_digit_in_checksum_id_is_redacted(text):
    out, key = _redact(text, "zh")
    assert len(key) >= 1, f"interior exotic ID not detected — leak: {text!r} -> {out!r}"
    assert ID not in out, f"ID leaked verbatim: {text!r} -> {out!r}"
    # The exotic digit must not survive in output either (folded to its ASCII value).
    assert AR["1"] not in out and DV["1"] not in out, f"exotic digit left in output: {out!r}"


# ── No-regression controls (must behave exactly as before the fix) ─────────────
def test_cjk_homograph_still_protects_both_name_and_phone():
    # 张三 = name whose 三 is a digit homograph (=3); the CJK-majority no-fold rule
    # keeps 三 intact so the phone's anchor still matches. BOTH must redact.
    out, key = _redact("客户张三13800138000", "zh")
    assert len(key) == 2, f"expected name+phone, got {key} -> {out!r}"
    assert PHONE not in out
    assert "张三" not in out


def test_space_separated_exotic_digit_still_redacts_the_phone():
    # A space between the phone and the exotic digit was already fine (the space is
    # the boundary); it must stay fine.
    out, key = _redact(f"电话{PHONE} {AR['9']}", "zh")
    assert len(key) >= 1
    assert PHONE not in out


def test_cjk_flanked_exotic_digit_is_left_untouched():
    # 一二三٤五六七 — ٤ is flanked by CJK numerals, not ASCII digits. It must NOT fold
    # (frozen behaviour); the mixed 7-char run is not a PII pattern → nothing redacts.
    out, key = _redact("一二三٤五六七", "zh")
    assert len(key) == 0
    assert AR["4"] in out  # the exotic digit survives verbatim


def test_clean_ascii_pii_unchanged():
    # Clean ASCII inputs redact exactly as before (no behaviour drift).
    for text, lang, secret in [
        (f"电话{PHONE}", "zh", PHONE),
        (f"公民身份号码{ID}", "zh", ID),
        (f"card {PAN}", "en", PAN),
    ]:
        out, key = _redact(text, lang)
        assert len(key) >= 1
        assert secret not in out


def test_genuine_chinese_numeral_phone_still_folds():
    # 一三八… (all-CJK number) still folds to ASCII and is detected + masked, as
    # before. The phone mask keeps first-3/last-4 visible (mapped back onto the
    # original CJK chars), so the frozen output is "电话一三八****八零零零" — the
    # security property is that it was DETECTED and the middle is masked.
    text = "电话一三八零零一三八零零零"
    out, key = _redact(text, "zh")
    assert len(key) >= 1
    assert out != text and "****" in out  # folded + detected + masked
