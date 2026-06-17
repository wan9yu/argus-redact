"""Tests for numeric range-noise fakers.

These differ from categorical reserved-range fakers: they take the original
value, parse the embedded number, and emit a noise-shifted variant within a
plausible range. The exact mapping is recorded in the key dict (by the caller).

Passthrough / identity cases (no digits, unrecognized format, invalid date
components, empty string) are golden-locked in Rust unit tests in
`crates/argus-redact-core/src/fakers.rs`:
  - `age_identity_when_no_digit` — covers no-digit and empty-string inputs
  - `dob_identity_on_invalid_or_no_match` — covers unrecognized/numeral formats
    AND the matched-but-invalid-calendar-date path (e.g. "1990-13-45"), asserting
    end-to-end identity at the faker level (not just the ymd_to_ordinal helper)
  - `date_roundtrip_and_known_offsets` — locks the ymd_to_ordinal/ordinal_to_ymd
    helpers and confirms invalid inputs return None
"""

import re
from datetime import date

import argus_redact._core as _core

_SALT = _core.resolve_salt(b"test-fakers-numeric-salt-here!!")


def _fake(faker_name: str, value: str, type_: str) -> tuple[str, list]:
    return _core.generate_unique_fake(faker_name, value, type_, _SALT, set())


class TestFakeAgeNoise:
    def test_should_extract_number_and_shift_within_band(self):
        result, aliases = _fake("fake_age_noise", "32岁", "age")
        assert aliases == []
        m = re.search(r"\d+", result)
        assert m is not None
        n = int(m.group())
        assert 25 <= n <= 40, f"Expected 25-40 (32 ±5 with cap), got {n}"
        assert "岁" in result, "Should preserve 岁 unit"

    def test_should_clamp_to_zero_floor(self):
        result, _ = _fake("fake_age_noise", "3岁", "age")
        n = int(re.search(r"\d+", result).group())
        assert n >= 0

    def test_should_clamp_to_149_ceiling(self):
        result, _ = _fake("fake_age_noise", "148岁", "age")
        n = int(re.search(r"\d+", result).group())
        assert n <= 149

    def test_should_preserve_keyword_format(self):
        result, _ = _fake("fake_age_noise", "年龄: 32", "age")
        assert "年龄" in result

    def test_should_be_deterministic(self):
        a, _ = _fake("fake_age_noise", "32岁", "age")
        b, _ = _fake("fake_age_noise", "32岁", "age")
        assert a == b


class TestFakeDateOfBirthNoise:
    def test_should_shift_dash_format_within_30_days(self):
        result, aliases = _fake("fake_date_of_birth_noise", "出生日期1990-03-15", "date_of_birth")
        assert aliases == []
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", result)
        assert m is not None
        year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
        original = date(1990, 3, 15)
        shifted = date(year, month, day)
        delta_days = abs((shifted - original).days)
        assert delta_days <= 30, f"Got delta {delta_days}d"
        assert result != "出生日期1990-03-15", "Identity mapping not avoided"

    def test_should_shift_slash_format(self):
        result, _ = _fake("fake_date_of_birth_noise", "出生日期1990/03/15", "date_of_birth")
        # Same separator preserved
        m = re.search(r"(\d{4})/(\d{2})/(\d{2})", result)
        assert m is not None
        original = date(1990, 3, 15)
        shifted = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        assert abs((shifted - original).days) <= 30

    def test_should_shift_dot_format(self):
        result, _ = _fake("fake_date_of_birth_noise", "出生日期1990.03.15", "date_of_birth")
        m = re.search(r"(\d{4})\.(\d{2})\.(\d{2})", result)
        assert m is not None

    def test_should_shift_chinese_year_month_day(self):
        result, _ = _fake("fake_date_of_birth_noise", "出生日期1990年3月15日", "date_of_birth")
        m = re.search(r"(\d{4})年(\d{1,2})月(\d{1,2})(日|号)", result)
        assert m is not None, f"Expected 年月日 format preserved, got {result}"
        original = date(1990, 3, 15)
        shifted = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        assert abs((shifted - original).days) <= 30
        assert m.group(4) == "日", "Should preserve 日/号 suffix"

    def test_should_shift_us_format(self):
        result, _ = _fake("fake_date_of_birth_noise", "DOB 03/15/1990", "date_of_birth")
        m = re.search(r"(\d{2})/(\d{2})/(\d{4})", result)
        assert m is not None
        original = date(1990, 3, 15)
        shifted = date(int(m.group(3)), int(m.group(1)), int(m.group(2)))
        assert abs((shifted - original).days) <= 30

    def test_should_keep_keyword(self):
        result, _ = _fake("fake_date_of_birth_noise", "出生日期1990-03-15", "date_of_birth")
        assert "出生" in result
