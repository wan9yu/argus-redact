"""Compare a current measurement JSON against a committed baseline.

Exit codes:
    0 — within ±10% on all workloads (or improvement)
    1 — any workload regressed >10%
"""

from __future__ import annotations

import argparse
import json
import os
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


def _annotate(level: str, title: str, lines: list[str]) -> None:
    """Emit a GitHub workflow annotation; a no-op outside Actions.

    Newlines have to be percent-encoded or the runner keeps only the first line.
    """
    if not os.environ.get("GITHUB_ACTIONS"):
        return
    body = "%0A".join(line.strip() for line in lines)
    print(f"::{level} title={title}::{body}")


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
        # Also emit the verdict as a workflow annotation. Stdout only reaches the
        # job log, which is not always retrievable; an annotation rides the API
        # the run page itself uses, so a red gate can explain itself from
        # anywhere — including to whoever has to decide whether the baseline or
        # the code is at fault.
        _annotate("error", f"Performance regression (>{_THRESHOLD:.0%})", regressions)
        return 1

    if improvements:
        print(f"Performance improved (>{_THRESHOLD:.0%} faster):")
        for line in improvements:
            print(line)
        print(
            "\nConsider running `make perf-update` to lock in the gain "
            "(updates tests/benchmark/baseline.json)."
        )

    # Report the measurements on a passing run too. Refreshing a baseline needs
    # numbers from the runner, and a green run is where the trustworthy ones are;
    # without this they exist only in the log and the artifact.
    _annotate(
        "notice",
        "Performance measurements",
        [f"- {k}: {v}ms" for k, v in sorted(current["measurements"].items())],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
