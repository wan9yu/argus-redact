#!/usr/bin/env python3
"""Generate the Chinese admin-region gazetteer RON from the GB/T 2260 TSV.

Reads ``tests/benchmark/data/gb2260.tsv`` (6-digit GB/T 2260 codes + names +
level) and writes ``crates/argus-redact-core/data/regions/zh.ron`` in the shape::

    ZhRegionData( regions: [
        ("name", "level", "city_name", "province_name"),
        ...
    ] )

where ``level`` is one of ``province`` / ``city`` / ``district``. Parentage is
derived purely from the code prefix:

* a district ``XXYYZZ`` belongs to city ``XXYY00`` and province ``XX0000``;
* a city ``XXYY00`` belongs to province ``XX0000`` and is its own ``city_name``;
* a province ``XX0000`` (incl. the four municipalities) is its own
  ``city_name`` and ``province_name``.

The four direct-administered municipalities (北京市 / 天津市 / 上海市 / 重庆市)
carry only a placeholder city row (市辖区 / 县) in GB/T 2260. Those placeholders
are dropped, and their districts map ``city_name = province_name = "<municipality>"``.

This is a generation-time tool only: it adds NO runtime dependency to the core.
The committed ``gb2260.tsv`` and the generated ``zh.ron`` are the reproducible
record. Re-run with ``python tests/benchmark/gen_regions.py``.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TSV = REPO_ROOT / "tests" / "benchmark" / "data" / "gb2260.tsv"
OUT = REPO_ROOT / "crates" / "argus-redact-core" / "data" / "regions" / "zh.ron"

# GB/T 2260 province codes for the four直辖市 (municipalities). Their districts
# roll up directly to the municipality, with no intermediate prefecture city.
MUNICIPALITY_CODES = {"110000", "120000", "310000", "500000"}

# Placeholder "city" names GB/T 2260 inserts under municipalities (e.g. 市辖区,
# 县) — never a real city, so they are never emitted nor used as a city_name.
PLACEHOLDER_CITY_NAMES = {"市辖区", "县"}


def level_of(code: str) -> str:
    if code.endswith("0000"):
        return "province"
    if code.endswith("00"):
        return "city"
    return "district"


def ron_safe(name: str) -> bool:
    """A name is RON-string-safe for our plain ``"..."`` tuples if it carries no
    quote / backslash / control char that would need escaping. GB/T 2260 names
    are CJK + a few ASCII letters, so anything else is a red flag worth skipping
    loudly rather than silently corrupting the RON."""
    return not any(ch in name for ch in ('"', "\\", "\n", "\r", "\t"))


def read_tsv() -> dict[str, tuple[str, str]]:
    """code -> (name, level). Comment lines (``#``) and the column header skipped."""
    table: dict[str, tuple[str, str]] = {}
    with TSV.open(encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            code, name, level = parts[0], parts[1], parts[2]
            if code == "code":  # column header
                continue
            table[code] = (name, level)
    return table


def build_rows(table: dict[str, tuple[str, str]]) -> list[tuple[str, str, str, str]]:
    """Return ordered (name, level, city_name, province_name) tuples."""
    skipped: list[tuple[str, str, str]] = []
    rows: list[tuple[str, str, str, str]] = []

    for code in sorted(table):
        name, level = table[code]
        prov_code = code[:2] + "0000"
        city_code = code[:4] + "00"

        prov_name = table.get(prov_code, (None,))[0]
        if prov_name is None:
            skipped.append((code, name, "missing province parent"))
            continue

        if level == "province":
            city_name = province_name = prov_name
        elif level == "city":
            # Drop the municipality placeholder "cities" (市辖区 / 县).
            if prov_code in MUNICIPALITY_CODES and name in PLACEHOLDER_CITY_NAMES:
                continue
            city_name = name
            province_name = prov_name
        else:  # district
            if prov_code in MUNICIPALITY_CODES:
                # Municipality districts roll up to the municipality itself.
                city_name = province_name = prov_name
            else:
                city_parent = table.get(city_code, (None,))[0]
                if city_parent is None or city_parent in PLACEHOLDER_CITY_NAMES:
                    skipped.append((code, name, "missing/placeholder city parent"))
                    continue
                city_name = city_parent
                province_name = prov_name

        unsafe = [v for v in (name, level, city_name, province_name) if not ron_safe(v)]
        if unsafe:
            skipped.append((code, name, f"RON-unsafe value(s): {unsafe}"))
            continue

        rows.append((name, level, city_name, province_name))

    if skipped:
        print(f"[gen_regions] skipped {len(skipped)} row(s):", file=sys.stderr)
        for code, name, why in skipped:
            print(f"  {code} {name}: {why}", file=sys.stderr)

    return rows


def write_ron(rows: list[tuple[str, str, str, str]]) -> None:
    lines = [
        "// Generated by tests/benchmark/gen_regions.py from gb2260.tsv "
        "(GB/T 2260, public-domain). DO NOT hand-edit.",
        "ZhRegionData(",
        "    regions: [",
    ]
    for name, level, city_name, province_name in rows:
        lines.append(f'        ("{name}", "{level}", "{city_name}", "{province_name}"),')
    lines.append("    ],")
    lines.append(")")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    table = read_tsv()
    rows = build_rows(table)
    write_ron(rows)
    n_prov = sum(1 for r in rows if r[1] == "province")
    n_city = sum(1 for r in rows if r[1] == "city")
    n_dist = sum(1 for r in rows if r[1] == "district")
    print(
        f"[gen_regions] wrote {OUT.relative_to(REPO_ROOT)}: "
        f"{len(rows)} regions ({n_prov} provinces, {n_city} cities, {n_dist} districts)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
