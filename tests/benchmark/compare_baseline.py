"""Compare a current measurement JSON against a committed baseline.

Exit codes:
    0 — within ±25% on all workloads (or improvement)
    1 — any workload regressed >25%
    2 — refused: platform/python mismatch, or a missing commit provenance label
        (see _check_provenance) — the two measurements are not comparable

Setting ARGUS_PERF_ADVISORY downgrades a *platform* mismatch from a refusal to a
printed advisory (for an intentional local cross-platform smoke comparison); a
python-minor mismatch or a missing commit label always refuses.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Regression gate: ±25% per workload — matches the shared-runner noise floor
# (see docs/perf-history.md; catches the O(n²)/GIL cliffs, which are multiples).
_THRESHOLD = 0.25


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


def _check_provenance(current: dict, baseline: dict) -> tuple[list[str], list[str]]:
    """Return (problems, warnings): problems make the comparison invalid (exit 2);
    warnings are printed but do not block.

    Platform and interpreter minor version both shift the perf floor enough
    that a delta computed across them is meaningless noise, not a signal — a
    macOS laptop run compared against the `ubuntu-latest` baseline could show
    either a phantom regression or a phantom improvement. `commit` is required
    too, but only as a provenance label to surface, never as an equality check:
    the baseline's `commit` field is free-text prose (e.g.
    "refresh-2026-07-27-ci-linux-min-of-7"), not a SHA the current run's git
    commit could ever match.

    With ARGUS_PERF_ADVISORY set, a *platform* mismatch is downgraded from a
    refusal to a warning (an intentional local cross-platform smoke run — `make
    perf-check` sets it). A python-minor mismatch or a missing commit label
    always refuses, advisory or not.
    """
    problems: list[str] = []
    warnings: list[str] = []
    advisory = bool(os.environ.get("ARGUS_PERF_ADVISORY"))

    cur_platform = current.get("platform")
    base_platform = baseline.get("platform")
    if cur_platform != base_platform:
        msg = (
            f"platform mismatch: current={cur_platform!r} vs baseline={base_platform!r} "
            "— measurements from different runner shapes are not comparable"
        )
        if advisory:
            warnings.append(f"ADVISORY (ARGUS_PERF_ADVISORY): {msg} — results indicative only")
        else:
            problems.append(msg)

    cur_python = current.get("python")
    base_python = baseline.get("python")
    if cur_python != base_python:
        problems.append(
            f"python mismatch: current={cur_python!r} vs baseline={base_python!r} "
            "(major.minor) — different interpreters have different perf floors"
        )

    for label, doc in (("current", current), ("baseline", baseline)):
        commit = doc.get("commit")
        if not commit or commit == "unknown":
            problems.append(f"{label} measurement has no commit/provenance label")

    return problems, warnings


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

    provenance_problems, provenance_warnings = _check_provenance(current, baseline)
    for warning in provenance_warnings:
        print(warning)
    if provenance_problems:
        print("Refusing to compare — provenance mismatch:")
        for problem in provenance_problems:
            print(f"  - {problem}")
        return 2

    # Provenance check passed: both sides carry a commit label. Print it — never
    # compare it for equality (see _check_provenance's docstring for why).
    print(f"current commit:  {current['commit']}")
    print(f"baseline commit: {baseline['commit']}")

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
            "\nConsider locking in the gain: `make perf-update` refuses outside "
            "GitHub Actions (a local machine's platform would fail this same "
            "provenance check against the committed baseline) — dispatch/re-run "
            "the perf.yml job on ubuntu-latest and commit the "
            "tests/benchmark/baseline.json it produces."
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
