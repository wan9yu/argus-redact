"""Numeric range-noise fakers (age, date_of_birth).

Unlike categorical reserved-range fakers, these depend on the original value
and produce a plausible-but-different number within a bounded band. Exact
mapping is recorded in the key dict by the caller (replacer.py).
"""

from __future__ import annotations

import random
import re
from datetime import date, timedelta


_AGE_BAND = 5  # ±5 years around original — preserves age-cohort statistics
_AGE_FLOOR = 0
_AGE_CEILING = 149


def fake_age_noise(value: str, rng: random.Random) -> str:
    """Shift the embedded age number by up to ±5 years, clamped to [0, 149].

    Returns the input unchanged if no digit is found.
    """
    m = re.search(r"\d+", value)
    if m is None:
        return value
    original = int(m.group())
    delta = rng.randint(-_AGE_BAND, _AGE_BAND)
    if delta == 0:
        # Avoid identity mapping (no-op fake exposes the original)
        delta = rng.choice((-1, 1))
    shifted = max(_AGE_FLOOR, min(_AGE_CEILING, original + delta))
    return value[: m.start()] + str(shifted) + value[m.end() :]


# ±30 days: large enough to be visibly different, small enough that
# downstream age-cohort / season statistics remain meaningful.
_DOB_BAND_DAYS = 30

# Format-specific patterns matching the date_of_birth regex in specs/zh.py:
# (1) YYYY年M月D日 / YYYY年M月D号 (Chinese)
# (2) YYYY[-/.]MM[-/.]DD (separator variants)
# (3) MM/DD/YYYY (US format)
# Chinese numeral months/days (e.g. "三月七号") are an explicit limitation —
# returned unchanged. See docs/known-issues.md.
_DOB_PATTERNS = (
    re.compile(r"(?P<y>\d{4})年(?P<m>\d{1,2})月(?P<d>\d{1,2})(?P<suffix>[日号])"),
    re.compile(r"(?P<y>\d{4})(?P<sep>[-/.])(?P<m>\d{1,2})[-/.](?P<d>\d{1,2})"),
    re.compile(r"(?P<m>\d{1,2})/(?P<d>\d{1,2})/(?P<y>\d{4})"),
)


def fake_date_of_birth_noise(value: str, rng: random.Random) -> str:
    """Shift the embedded date by up to ±30 days. Preserves the original format.

    Recognizes:
      - YYYY年M月D日 / YYYY年M月D号
      - YYYY-MM-DD, YYYY/MM/DD, YYYY.MM.DD
      - MM/DD/YYYY
    Returns input unchanged if no recognized format is found, or if components
    don't form a valid date (e.g. month=13, day=32).
    """
    for pat_index, pat in enumerate(_DOB_PATTERNS):
        m = pat.search(value)
        if m is None:
            continue
        try:
            original = date(int(m.group("y")), int(m.group("m")), int(m.group("d")))
        except ValueError:
            return value
        delta = rng.randint(-_DOB_BAND_DAYS, _DOB_BAND_DAYS)
        if delta == 0:
            # Avoid identity mapping (1 week guarantees same-month bias is rare)
            delta = rng.choice((-7, 7))
        shifted = original + timedelta(days=delta)
        if pat_index == 0:  # YYYY年M月D日/号
            new_text = f"{shifted.year:04d}年{shifted.month}月{shifted.day}{m.group('suffix')}"
        elif pat_index == 1:  # YYYY[-/.]MM[-/.]DD
            sep = m.group("sep")
            new_text = f"{shifted.year:04d}{sep}{shifted.month:02d}{sep}{shifted.day:02d}"
        else:  # MM/DD/YYYY
            new_text = f"{shifted.month:02d}/{shifted.day:02d}/{shifted.year:04d}"
        return value[: m.start()] + new_text + value[m.end() :]
    return value
