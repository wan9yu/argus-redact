"""Architecture: marketing/landing claims must match shipped capabilities.

As of v0.5.10 the four individual ID types (HKID / TWID / Macau / Taiwan
ARC) are shipped, so they no longer need a qualifier. What still needs a
qualifier is the *umbrella* claim — "港澳台证件" / "all of HK/TW/Macau" —
because "all three" implies coverage parity v0.x does not provide (e.g.
legacy ARC, certain HKID edge cases). So this guard triggers on the
umbrella, NOT on individual mentions of 香港 / 澳门 / 台湾.

The test exists because we shipped a reply to downstream documenting the
gap; future maintainers should not silently overclaim again.

Two deliberate design points:
- README.zh.md is scanned (it is user-facing — README.md links to it — and
  is the natural home for a Chinese overclaim like 港澳台证件).
- ``test_overclaim_guard_is_not_vacuous`` is a positive control: the main
  test passes today only because no umbrella claim is present, which on its
  own is an unfalsifiable green. The positive control proves the guard still
  discriminates (catches an unqualified umbrella claim; lets a scoped one
  through), so the guard can never silently rot into a tautology.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Files that face users / customers and must not overclaim.
_USER_FACING = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "README.zh.md",
    REPO_ROOT / "docs" / "whitepaper-chinese-pii.md",
    REPO_ROOT / "docs" / "sensitive-info.md",
    REPO_ROOT / "docs" / "getting-started.md",
]

# Patterns whose appearance suggests an *umbrella* HK/TW/Macau coverage claim.
# If found, the surrounding 200-char context must include a scope qualifier
# (see _QUALIFIERS). We trigger on the umbrella only — bare 香港 / 澳门 / 台湾
# mentions are fine because the four individual ID types shipped in v0.5.10.
_COVERAGE_TRIGGERS = (
    # 港澳台 + a coverage noun/claim (catches 港澳台证件, 港澳台身份证全覆盖, …).
    r"港澳台[^\n。！？;；]{0,10}(?:证件|身份证|居民|全覆盖|全部支持|都支持|均支持|全面支持|完整支持)",
    # English umbrella variant: full/complete/all HK + TW + Macau.
    r"(?:full|complete|all)\s+(?:HK|Hong\s*Kong)\W+(?:TW|Taiwan)\W+(?:Macau|Macao)",
)

# A qualifier within 200 chars scopes the claim and clears the trigger. Mixed
# English + Chinese so a legitimately-scoped Chinese claim is not false-flagged.
_QUALIFIERS = (
    "out of scope",
    "roadmap",
    "v0.6",
    "not covered",
    "deferred",
    "超出范围",
    "路线图",
    "未覆盖",
    "暂不支持",
    "尚未支持",
    "计划中",
    "已推迟",
)

_COVERAGE_PATTERN = re.compile("|".join(_COVERAGE_TRIGGERS), re.IGNORECASE)


def _unqualified_claims(text: str) -> list[str]:
    """Umbrella coverage claims in ``text`` lacking a qualifier within 200 chars."""
    low = text.lower()
    hits = []
    for m in _COVERAGE_PATTERN.finditer(text):
        ctx = low[max(0, m.start() - 200) : m.end() + 200]
        if not any(marker in ctx for marker in _QUALIFIERS):
            hits.append(m.group())
    return hits


def test_no_overclaim_hk_tw_macau():
    for path in _USER_FACING:
        if not path.exists():
            continue
        hits = _unqualified_claims(path.read_text(encoding="utf-8"))
        assert not hits, (
            f"{path.name} makes umbrella HK/TW/Macau coverage claim(s) {hits} "
            f"without an out-of-scope / roadmap / 路线图 qualifier within 200 "
            f"chars. Either scope the claim or remove it."
        )


def test_overclaim_guard_is_not_vacuous():
    # Positive control — proves the guard discriminates rather than passing
    # vacuously. If this breaks, the main test's green is meaningless.
    assert _unqualified_claims("本工具支持港澳台证件全覆盖。"), (
        "guard failed to catch an unqualified Chinese umbrella claim"
    )
    assert _unqualified_claims("Full HK / TW / Macau ID coverage out of the box."), (
        "guard failed to catch an unqualified English umbrella claim"
    )
    # A scoped umbrella claim must pass (no false positive on honest docs).
    assert not _unqualified_claims("港澳台证件全覆盖（暂未覆盖部分边缘情况，见路线图）。"), (
        "guard false-flagged a properly-scoped Chinese claim"
    )
    # An individual shipped type must never trip the umbrella guard.
    assert not _unqualified_claims("支持香港居民身份证。"), (
        "guard false-flagged an individual (shipped) ID type"
    )
