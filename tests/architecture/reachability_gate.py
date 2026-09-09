"""Reachability gate: catches a collected test that never actually runs.

A test can be silently deselected forever -- gated behind a marker no CI
leg ever runs without, a fixture that always skips, a typo in a marker
expression -- and the suite stays green because nothing ever asks "did
every collected test id run somewhere?". This script asks exactly that.

It computes the canonical test inventory with a collection that never
deselects on markers (`-m ""` on the command line overrides any
`addopts`/ini marker expression, so nothing gated behind `ner`/`semantic`/
`slow` disappears from the count), then unions the tests that actually
executed across every junit-xml file handed to it. Anything collected but
never executed anywhere is reported, unless it has a written reason in
ALLOWLIST.

Usage:
    python tests/architecture/reachability_gate.py junit-*.xml
"""

from __future__ import annotations

import glob
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parents[2]

COLLECT_ONLY_CMD = [
    sys.executable,
    "-m",
    "pytest",
    "--collect-only",
    "-q",
    "-m",
    "",
    "-p",
    "no:cacheprovider",
]

# Test ids that are deliberately never executed by any CI leg today, each
# with the reason written out. Keep this empty unless a specific id has a
# documented reason to be exempt from the gate -- an entry here silences a
# real gap, so it should be rare and explicit, never a blanket pattern.
ALLOWLIST: dict[str, str] = {}


def mangle_test_address(address: str) -> list[str]:
    """Reproduce `_pytest.junitxml.mangle_test_address` so a collect-only
    nodeid (`tests/pkg/test_mod.py::Class::test_fn[param]`) and a junit
    `classname`+`name` pair land on the exact same canonical string.
    """
    path, bracket, params = address.partition("[")
    names = path.split("::")
    names[0] = names[0].replace("/", ".")
    if names[0].endswith(".py"):
        names[0] = names[0][: -len(".py")]
    names[-1] += bracket + params
    return names


def canonical_id(nodeid: str) -> str:
    return ".".join(mangle_test_address(nodeid))


def parse_collect_only_output(output: str) -> set[str]:
    """Extract canonical test ids from `pytest --collect-only -q` stdout.

    Every real nodeid line contains ``.py::`` (the file path always ends
    in ``.py`` right before the first ``::``); the trailing summary line
    ("N tests collected in Ys") and any collection-error/warning noise do
    not, so that substring is a safe, simple filter.
    """
    ids = set()
    for line in output.splitlines():
        line = line.strip()
        if ".py::" not in line:
            continue
        ids.add(canonical_id(line))
    return ids


def collect_inventory(cwd: Path = REPO_ROOT) -> set[str]:
    """Run the canonical, non-deselecting collection and return its ids."""
    proc = subprocess.run(
        COLLECT_ONLY_CMD,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    # 0 = tests collected, 5 = no tests collected (an empty suite is still
    # a valid, if useless, answer). Anything else means collection itself
    # is broken -- surface the failure instead of silently diffing against
    # a truncated inventory.
    if proc.returncode not in (0, 5):
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise RuntimeError(f"canonical inventory collection failed (exit {proc.returncode})")
    return parse_collect_only_output(proc.stdout)


def classify_testcase(testcase: ET.Element) -> bool:
    """Return True if `testcase` counts as EXECUTED (ran to a pass,
    failure, error, or an xfail outcome), False if it never ran (a real
    skip, or a collection-time skip).
    """
    skipped = testcase.find("skipped")
    if skipped is None:
        # <testcase> with no <skipped> child: passed, or has a <failure>/
        # <error> child -- all three mean the test body actually ran.
        return True

    skip_type = skipped.get("type")
    if skip_type == "pytest.xfail":
        # Expected-fail, ran and failed as expected.
        return True
    if skip_type == "pytest.skip":
        # skipif/pytest.skip() -- setup ran but the test body never did.
        return False

    # Typeless <skipped>: either an xfail that passed unexpectedly
    # (reported as a skip, but the body ran -- executed) or a
    # collection-time skip such as `pytest.importorskip` (the module
    # never imported, so nothing in it ran).
    return skipped.get("message", "") == "xfail-marked test passes unexpectedly"


def parse_junit_executions(path: Path) -> dict[str, bool]:
    """Map every testcase id in `path` to whether it counts as executed."""
    root = ET.parse(path).getroot()
    results: dict[str, bool] = {}
    for testcase in root.iter("testcase"):
        classname = testcase.get("classname", "")
        name = testcase.get("name", "")
        tc_id = f"{classname}.{name}" if classname else name
        executed = classify_testcase(testcase)
        # A rerun could list the same id twice; one execution is enough.
        results[tc_id] = results.get(tc_id, False) or executed
    return results


def resolve_junit_paths(args: list[str]) -> list[Path]:
    paths: list[Path] = []
    seen: set[str] = set()
    for arg in args:
        matches = sorted(glob.glob(arg)) or ([arg] if Path(arg).is_file() else [])
        for match in matches:
            if match not in seen:
                seen.add(match)
                paths.append(Path(match))
    return paths


def union_executions(paths: list[Path]) -> tuple[set[str], dict[str, int]]:
    executed: set[str] = set()
    per_leg_counts: dict[str, int] = {}
    for path in paths:
        results = parse_junit_executions(path)
        per_leg_counts[str(path)] = len(results)
        executed.update(tc_id for tc_id, ok in results.items() if ok)
    return executed, per_leg_counts


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: reachability_gate.py <junit-xml> [...]", file=sys.stderr)
        return 2

    junit_paths = resolve_junit_paths(argv)
    if not junit_paths:
        print(f"no junit files matched: {argv!r}", file=sys.stderr)
        return 2

    inventory = collect_inventory()
    executed, per_leg_counts = union_executions(junit_paths)

    never_run = sorted(inventory - executed)
    allowlisted = [tc_id for tc_id in never_run if tc_id in ALLOWLIST]
    unexplained = [tc_id for tc_id in never_run if tc_id not in ALLOWLIST]
    largest_leg = max(per_leg_counts.values(), default=0)

    print(f"canonical inventory: {len(inventory)} test ids")
    for leg, count in sorted(per_leg_counts.items()):
        print(f"  leg {leg}: {count} testcases")
    print(f"executed union: {len(executed)} test ids")
    if allowlisted:
        print(f"allowlisted never-run: {len(allowlisted)}")
        for tc_id in allowlisted:
            print(f"  ALLOWLISTED: {tc_id} -- {ALLOWLIST[tc_id]}")

    ok = True

    if len(inventory) <= largest_leg:
        ok = False
        print(
            f"SELF-CHECK FAILED: inventory ({len(inventory)}) is not larger than "
            f"the largest single leg ({largest_leg}). Either the canonical "
            "collection ('-m \"\"') did not override the marker deselect, or "
            "too few junit files were passed in.",
            file=sys.stderr,
        )

    if unexplained:
        ok = False
        print(f"NEVER-RUN on any provided leg ({len(unexplained)}):", file=sys.stderr)
        for tc_id in unexplained:
            print(f"  {tc_id}", file=sys.stderr)

    if ok:
        print("reachability gate: OK")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
