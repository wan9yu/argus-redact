"""Architecture: marketing/landing claims must match shipped capabilities.

Specifically: HK / TW / Macau / Taiwan ARC IDs are NOT covered in v0.5.x.
This test fails if README, docs/, or marketing/ start claiming coverage of
those types without explicit "Out of scope" or "Roadmapped" qualifier
within 200 chars of the claim.

The test exists because we shipped a reply to downstream documenting the
gap; future maintainers should not silently overclaim again.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Files that face users / customers and must not overclaim.
_USER_FACING = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs" / "whitepaper-chinese-pii.md",
    REPO_ROOT / "docs" / "sensitive-info.md",
    REPO_ROOT / "docs" / "getting-started.md",
]

# Strings whose appearance suggests a coverage claim. If found, the
# surrounding 200-char context must include an "out of scope" / "roadmap" /
# "v0.6" disclaimer.
_COVERAGE_TRIGGERS = (
    "港澳台证件",
    "HKID",
    "台湾身份证",
    "澳门身份证",
    "Taiwan ARC",
    "Hong Kong ID",
    "Macau ID",
)


_QUALIFIERS = ("out of scope", "roadmap", "v0.6", "not covered", "deferred")
_COVERAGE_PATTERN = re.compile("|".join(re.escape(t) for t in _COVERAGE_TRIGGERS))


def test_no_overclaim_hk_tw_macau():
    for path in _USER_FACING:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for m in _COVERAGE_PATTERN.finditer(text):
            ctx = text[max(0, m.start() - 200) : m.end() + 200].lower()
            qualified = any(marker in ctx for marker in _QUALIFIERS)
            assert qualified, (
                f"{path.name} contains {m.group()!r} without an "
                f"out-of-scope / roadmap qualifier within 200 chars. "
                f"Either add the qualifier or remove the claim."
            )
