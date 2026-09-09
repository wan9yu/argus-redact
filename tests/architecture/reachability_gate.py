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
never executed anywhere is reported as a real gap.

Two kinds of never-run are EXPECTED, not gaps:

* Model-gated tests. No CI leg installs the NER / Layer-3 models, so every
  test marked `ner`, `semantic`, or `slow` is never-run *by design*. Rather
  than list all of them one by one, the gate computes the model-gated set
  with a second canonical collection (`-m "ner or semantic or slow"`) and
  treats a never-run id in that set as expected. This stays correct as
  model-gated tests are added or removed -- nothing to maintain by hand.
* Explicit ALLOWLIST entries. A never-run id that is deliberately exempt for
  a NON-marker reason carries a written justification in ALLOWLIST.

A never-run id that is neither model-gated nor allowlisted is the real
failure this gate exists to catch.

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

# Marker expression whose collection is the model-gated set: tests that no
# CI leg runs because no leg installs the NER / Layer-3 models. A never-run
# id collected under this expression is expected, not a gap -- see module
# docstring.
MODEL_GATED_MARKER_EXPR = "ner or semantic or slow"

# Test ids that are deliberately never executed by any CI leg today for a
# reason OTHER than a model-gated marker, each with the reason written out.
# Keep this rare and explicit -- an entry here silences a real gap, so it is
# never a blanket pattern. (Model-gated tests do not belong here; the marker
# collection above covers them without hand maintenance.)
_ADVERSARIAL_NO_COUNT = (
    "false-positive / near-miss corpus entries carry no expected_pii_count, so the "
    "count assertion skips them; they are still exercised by the no-crash and "
    "roundtrip cases in the same parametrized class"
)
_REALISTIC_NO_PII = (
    "no-PII / edge corpus entries carry no pii_values, so the detect and roundtrip "
    "assertions skip them; they are still exercised by the no-crash case in the same "
    "parametrized class"
)
_GUARD_NO_DETAILED = (
    "this backend exposes no per-call detailed= argument (the langchain/llamaindex "
    "'Pattern A' recipes and the mcp restore tool return a fixed shape), so the "
    "per-call detailed-events assertion is inapplicable; the backend's other "
    "guard-contract assertions still run"
)

ALLOWLIST: dict[str, str] = {
    # -- Superseded performance harness -------------------------------------
    # Superseded by the operation-count performance gates; kept only until
    # the structured-redaction proximity scan is linearized, at which point
    # this whole file is deleted. It is also model-gated (`pytestmark =
    # pytest.mark.slow`, so the marker collection already exempts it); this
    # explicit entry records that the exemption is deliberate and temporary.
    "tests.benchmark.test_structured_linear.test_per_cell_cost_is_flat_in_n": (
        "superseded by the operation-count performance gates; deleted when the "
        "structured-redaction proximity scan is linearized"
    ),
    "tests.benchmark.test_structured_linear.test_intermediate_size_confirms_scaling": (
        "superseded by the operation-count performance gates; deleted when the "
        "structured-redaction proximity scan is linearized"
    ),
    # -- External-service contract check ------------------------------------
    # Runs only against a populated PRvL baseline behind an external LLM API
    # key; the repo ships the baseline as an empty placeholder and no CI leg
    # provides the key, so the shape check has nothing to assert.
    "tests.benchmark.test_prvl_v0_5_x.TestPRvLv0_5xBaselineFixtureContract."
    "test_fixture_shape_when_present": (
        "PRvL baseline fixture ships as an empty placeholder; this shape check runs "
        "only against a populated baseline, which needs an external LLM API key no CI "
        "leg provides"
    ),
    # -- Parity check with a removed data source ----------------------------
    # The Python-side person-name data source these compared the Rust core
    # against was removed; the tests are retained as the documented parity
    # contract but skip unconditionally until a Python-side source returns.
    "tests.detection.lang.test_person_data_parity.test_core_pools_equal_python_source": (
        "the Python person-name data source this compared against was removed; retained "
        "as a documented parity contract with nothing to run until a Python-side source "
        "returns"
    ),
    "tests.detection.lang.test_person_data_parity.test_python_source_matches_frozen_fingerprints": (
        "the Python person-name data source this compared against was removed; retained "
        "as a documented parity contract with nothing to run until a Python-side source "
        "returns"
    ),
    # -- Backend-inapplicable guard-contract parametrizations ---------------
    "tests.integration.test_guard_contract."
    "test_detailed_events_are_h_only_when_reachable[langchain]": _GUARD_NO_DETAILED,
    "tests.integration.test_guard_contract."
    "test_detailed_events_are_h_only_when_reachable[llamaindex]": _GUARD_NO_DETAILED,
    "tests.integration.test_guard_contract."
    "test_detailed_events_are_h_only_when_reachable[mcp]": _GUARD_NO_DETAILED,
    # -- Data-conditional adversarial parametrizations (no expected count) --
    "tests.safety.test_adversarial.TestAdversarial."
    "test_should_detect_expected_count[adv_many_near_miss_numbers]": _ADVERSARIAL_NO_COUNT,
    "tests.safety.test_adversarial.TestAdversarial."
    "test_should_detect_expected_count[fp_hex_looks_like_passport]": _ADVERSARIAL_NO_COUNT,
    "tests.safety.test_adversarial.TestAdversarial."
    "test_should_detect_expected_count[fp_math_expression_zh_phone]": _ADVERSARIAL_NO_COUNT,
    "tests.safety.test_adversarial.TestAdversarial."
    "test_should_detect_expected_count[fp_order_number_looks_like_id]": _ADVERSARIAL_NO_COUNT,
    "tests.safety.test_adversarial.TestAdversarial."
    "test_should_detect_expected_count[fp_product_code_16_digits]": _ADVERSARIAL_NO_COUNT,
    "tests.safety.test_adversarial.TestAdversarial."
    "test_should_detect_expected_count[fp_version_number_as_ssn]": _ADVERSARIAL_NO_COUNT,
    # -- Data-conditional realistic parametrizations (no PII to detect) ------
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_detect_pii[edge_multiline_pii_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_detect_pii[edge_no_pii_de_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_detect_pii[edge_no_pii_en_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_detect_pii[edge_no_pii_zh_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_detect_pii[edge_unicode_obfuscation_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_detect_pii[edge_zh_phone_no_separator_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_roundtrip[edge_multiline_pii_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_roundtrip[edge_no_pii_de_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_roundtrip[edge_no_pii_en_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_roundtrip[edge_no_pii_zh_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_roundtrip[edge_unicode_obfuscation_01]": _REALISTIC_NO_PII,
    "tests.safety.test_realistic.TestRealisticScenarios."
    "test_should_roundtrip[edge_zh_phone_no_separator_01]": _REALISTIC_NO_PII,
}


def _collect_only_cmd(marker_expr: str) -> list[str]:
    """The canonical, cache-disabled collect-only command for `marker_expr`.

    A literal `-m` on the command line overrides any `addopts`/ini marker
    expression, so `""` collects the whole suite and `"ner or semantic or
    slow"` collects exactly the model-gated subset.
    """
    return [
        sys.executable,
        "-m",
        "pytest",
        "--collect-only",
        "-q",
        "-m",
        marker_expr,
        "-p",
        "no:cacheprovider",
    ]


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


def _collect_ids(marker_expr: str, cwd: Path = REPO_ROOT) -> set[str]:
    """Run a canonical collect-only for `marker_expr` and return its ids."""
    proc = subprocess.run(
        _collect_only_cmd(marker_expr),
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    # 0 = tests collected, 5 = no tests collected (an empty result is still
    # a valid, if useless, answer). Anything else means collection itself
    # is broken -- surface the failure instead of silently diffing against
    # a truncated inventory.
    if proc.returncode not in (0, 5):
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise RuntimeError(
            f"canonical collection for marker {marker_expr!r} failed (exit {proc.returncode})"
        )
    return parse_collect_only_output(proc.stdout)


def collect_inventory(cwd: Path = REPO_ROOT) -> set[str]:
    """Run the canonical, non-deselecting collection and return its ids."""
    return _collect_ids("", cwd)


def collect_model_gated(cwd: Path = REPO_ROOT) -> set[str]:
    """Collect the model-gated ids (`ner`/`semantic`/`slow`) -- never-run by
    design because no CI leg installs the NER / Layer-3 models."""
    return _collect_ids(MODEL_GATED_MARKER_EXPR, cwd)


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
    model_gated = collect_model_gated()
    executed, per_leg_counts = union_executions(junit_paths)

    never_run = sorted(inventory - executed)
    # An explicit ALLOWLIST entry documents a deliberate, non-marker
    # exemption, so it takes precedence in the report; the model-gated set
    # then covers everything gated behind `ner`/`semantic`/`slow`. Whatever
    # is left is a real gap.
    allowlisted = [tc_id for tc_id in never_run if tc_id in ALLOWLIST]
    marker_exempt = [
        tc_id for tc_id in never_run if tc_id not in ALLOWLIST and tc_id in model_gated
    ]
    unexplained = [
        tc_id for tc_id in never_run if tc_id not in ALLOWLIST and tc_id not in model_gated
    ]
    largest_leg = max(per_leg_counts.values(), default=0)

    print(f"canonical inventory: {len(inventory)} test ids")
    print(f"model-gated (ner/semantic/slow) inventory: {len(model_gated)} test ids")
    for leg, count in sorted(per_leg_counts.items()):
        print(f"  leg {leg}: {count} testcases")
    print(f"executed union: {len(executed)} test ids")
    print(
        f"never-run: {len(never_run)} (model-gated {len(marker_exempt)}, allowlisted "
        f"{len(allowlisted)}, unexplained {len(unexplained)})"
    )
    if allowlisted:
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

    stray = model_gated - inventory
    if not model_gated or stray:
        ok = False
        print(
            "SELF-CHECK FAILED: the model-gated collection "
            f"({MODEL_GATED_MARKER_EXPR!r}) is empty or not a subset of the "
            f"inventory (empty={not model_gated}, stray={len(stray)}). A broken "
            "marker collection would wrongly exempt (or fail to exempt) the "
            "NER / Layer-3 tests.",
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
