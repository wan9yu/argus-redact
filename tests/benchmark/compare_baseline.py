"""Compare a current measurement JSON against a committed baseline.

Exit codes:
    0 — within ±10% on all workloads (or improvement)
    1 — any workload regressed >10%
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


_THRESHOLD = 0.10  # regression gate: ±10% per workload (see docs/perf-history.md)


def _compare(current: dict, baseline: dict) -> tuple[list[str], list[str]]:
    """Return (regressions, improvements) — each a list of human-readable lines."""
    regressions: list[str] = []
    improvements: list[str] = []
    cur_m = current["measurements"]
    base_m = baseline["measurements"]

    for key, base_val in base_m.items():
        if key not in cur_m:
            regressions.append(f"  - {key}: missing in current measurement")
            continue
        cur_val = cur_m[key]
        if base_val <= 0:
            continue
        delta = (cur_val - base_val) / base_val
        line = f"  - {key}: {base_val:.2f}ms → {cur_val:.2f}ms ({delta:+.1%})"
        if delta > _THRESHOLD:
            regressions.append(line)
        elif delta < -_THRESHOLD:
            improvements.append(line)

    return regressions, improvements


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("current_json")
    parser.add_argument("baseline_json")
    args = parser.parse_args()

    current = json.loads(Path(args.current_json).read_text(encoding="utf-8"))
    baseline = json.loads(Path(args.baseline_json).read_text(encoding="utf-8"))

    regressions, improvements = _compare(current, baseline)

    if regressions:
        print(f"Performance regressions detected (>{_THRESHOLD:.0%} slower):")
        for line in regressions:
            print(line)
        return 1

    if improvements:
        print(f"Performance improved (>{_THRESHOLD:.0%} faster):")
        for line in improvements:
            print(line)
        print(
            "\nConsider running `make perf-update` to lock in the gain "
            "(updates tests/benchmark/baseline.json)."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
