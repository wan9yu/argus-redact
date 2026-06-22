"""Gated structural test for the re-identification eval (PRvL+ X axis).

DOUBLE-GATED, off by default:
  1. marked semantic+slow → deselected by the default CI run
     (`-m "not ner and not semantic and not slow"`); AND
  2. requires an EXPLICIT opt-in env flag `ARGUS_REID_EVAL=1`.
So it NEVER fires on a plain `pytest` run — even when an LLM API key happens to be
present in the environment (it makes paid LLM calls). To run it you must opt in AND
have a backend (an API key, or a local Ollama). Asserts the harness runs end-to-end
and produces a well-formed snapshot; does NOT assert exact re-id rates (LLM
nondeterminism — the directional result raw >= argus_fast is REPORTED, not gated).
"""
import os
import pytest
# NOTE: httpx is imported LAZILY inside _backend_available() — it is not a declared
# dependency, so a module-top import would crash collection (and red CI) on envs
# without it, even though this test is deselected there.

from tests.benchmark.reid_eval import PROVIDERS, available_providers, run_eval

pytestmark = [pytest.mark.semantic, pytest.mark.slow]

# Explicit opt-in: presence of an API key is NOT enough — the maintainer must set
# ARGUS_REID_EVAL=1 so this never runs (and never bills) by accident.
_OPT_IN = os.environ.get("ARGUS_REID_EVAL") == "1"


def _backend_available() -> bool:
    provs = available_providers()
    if any(p != "ollama" for p in provs):
        return True
    if "ollama" in provs:
        try:
            import httpx
            httpx.get("http://localhost:11434/api/tags", timeout=2.0)
            return True
        except Exception:  # noqa: BLE001
            return False
    return False


@pytest.mark.skipif(
    not (_OPT_IN and _backend_available()),
    reason="off by default — set ARGUS_REID_EVAL=1 (+ an LLM API key or local Ollama) to run; makes paid LLM calls",
)
def test_reid_harness_runs_and_snapshot_is_wellformed():
    snap = run_eval(provider=None, model=None, limit=4)  # tiny subset → cheap
    assert snap["benchmark"] == "reidentification"
    assert set(snap["redactors"]) == {"raw", "argus_fast"}
    for name, r in snap["redactors"].items():
        assert r["n"] >= 1, f"{name}: no profiles evaluated"
        assert r["reid_rate"] is None or 0.0 <= r["reid_rate"] <= 1.0
        assert len(r["per_profile"]) == r["n"]
        for row in r["per_profile"]:
            assert set(row) == {"truth", "guess"}
