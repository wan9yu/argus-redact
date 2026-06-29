"""produce_hints is a parity-test-only oracle; no production module may import it."""

import pathlib
import re

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "argus_redact"

# Matches the bare symbol name "produce_hints" when NOT immediately followed
# by the "_l1" suffix (i.e. excludes "produce_hints_l1").
_PAT = re.compile(r"\bproduce_hints\b(?!_l1)")


def test_produce_hints_has_no_production_caller():
    offenders = []
    for py in SRC.rglob("*.py"):
        if py.name == "hints.py":
            continue  # the definition site itself
        if _PAT.search(py.read_text(encoding="utf-8")):
            offenders.append(str(py.relative_to(SRC)))
    assert offenders == [], f"produce_hints used in production module(s): {offenders}"
