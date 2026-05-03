"""Tests for numeric range-noise fakers.

These differ from categorical reserved-range fakers: they take the original
value, parse the embedded number, and emit a noise-shifted variant within a
plausible range. The exact mapping is recorded in the key dict (by the caller).
"""

import random
import re
from datetime import date

from argus_redact.specs.fakers_numeric import (
    fake_age_noise,
    fake_date_of_birth_noise,
)


class TestFakeAgeNoise:
    def test_should_extract_number_and_shift_within_band(self):
        result, aliases = fake_age_noise("32岁", random.Random(1))
        assert aliases == []
        m = re.search(r"\d+", result)
        assert m is not None
        n = int(m.group())
        assert 25 <= n <= 40, f"Expected 25-40 (32 ±5 with cap), got {n}"
        assert "岁" in result, "Should preserve 岁 unit"

    def test_should_clamp_to_zero_floor(self):
        result, _ = fake_age_noise("3岁", random.Random(1))
        n = int(re.search(r"\d+", result).group())
        assert n >= 0

    def test_should_clamp_to_149_ceiling(self):
        result, _ = fake_age_noise("148岁", random.Random(1))
        n = int(re.search(r"\d+", result).group())
        assert n <= 149

    def test_should_preserve_keyword_format(self):
        result, _ = fake_age_noise("年龄: 32", random.Random(1))
        assert "年龄" in result

    def test_should_be_deterministic(self):
        a = fake_age_noise("32岁", random.Random(7))
        b = fake_age_noise("32岁", random.Random(7))
        assert a == b

    def test_should_return_unchanged_when_no_digits(self):
        assert fake_age_noise("年龄未知", random.Random(1)) == ("年龄未知", [])

    def test_should_return_empty_string_unchanged(self):
        assert fake_age_noise("", random.Random(1)) == ("", [])


class TestFakeDateOfBirthNoise:
    def test_should_shift_dash_format_within_30_days(self):
        result, aliases = fake_date_of_birth_noise("出生日期1990-03-15", random.Random(1))
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
        result, _ = fake_date_of_birth_noise("出生日期1990/03/15", random.Random(1))
        # Same separator preserved
        m = re.search(r"(\d{4})/(\d{2})/(\d{2})", result)
        assert m is not None
        original = date(1990, 3, 15)
        shifted = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        assert abs((shifted - original).days) <= 30

    def test_should_shift_dot_format(self):
        result, _ = fake_date_of_birth_noise("出生日期1990.03.15", random.Random(1))
        m = re.search(r"(\d{4})\.(\d{2})\.(\d{2})", result)
        assert m is not None

    def test_should_shift_chinese_year_month_day(self):
        result, _ = fake_date_of_birth_noise("出生日期1990年3月15日", random.Random(1))
        m = re.search(r"(\d{4})年(\d{1,2})月(\d{1,2})(日|号)", result)
        assert m is not None, f"Expected 年月日 format preserved, got {result}"
        original = date(1990, 3, 15)
        shifted = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        assert abs((shifted - original).days) <= 30
        assert m.group(4) == "日", "Should preserve 日/号 suffix"

    def test_should_shift_us_format(self):
        result, _ = fake_date_of_birth_noise("DOB 03/15/1990", random.Random(1))
        m = re.search(r"(\d{2})/(\d{2})/(\d{4})", result)
        assert m is not None
        original = date(1990, 3, 15)
        shifted = date(int(m.group(3)), int(m.group(1)), int(m.group(2)))
        assert abs((shifted - original).days) <= 30

    def test_should_keep_keyword(self):
        result, _ = fake_date_of_birth_noise("出生日期1990-03-15", random.Random(1))
        assert "出生" in result

    def test_should_return_unchanged_when_unrecognized_format(self):
        # Chinese numeral format is an explicit limitation
        assert fake_date_of_birth_noise("出生三月七号", random.Random(1)) == ("出生三月七号", [])

    def test_should_return_unchanged_when_invalid_date_components(self):
        # Month=13 fails date() construction → return unchanged
        assert fake_date_of_birth_noise("1990-13-45", random.Random(1)) == ("1990-13-45", [])
