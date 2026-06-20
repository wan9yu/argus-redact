"""Guard the saved benchmark-result JSON shape produced by ``--save``.

The CLI (``python -m tests.benchmark ... --save PATH``) writes a result JSON the
floor tests and README tables read. This pins the enriched shape:

  * ``package_version_string`` — the package's self-reported ``__version__`` (so
    a result file records which build produced it, independent of the human
    ``version`` label).
  * per-mode ``per_type`` — the per-type {precision,recall,f1,tp,fp,fn} the
    evaluator already computes, exposed both nested under ``modes[mode]`` and
    flat as ``per_type_{mode}`` (the form the en precision-floor test reads).

Backward compat: the legacy ``modes[mode].{precision,recall,f1}`` overall fields
and the top-level ``version`` / ``dataset`` / ``samples`` fields are retained, so
the older schema-guard tests (e.g. test_ai4privacy_0_6_6_results_loaded) still
pass.
"""

from __future__ import annotations

from argus_redact import __version__
from tests.benchmark.__main__ import build_payload
from tests.benchmark.model import Result, TypeMetrics


def _fast_result() -> Result:
    r = Result(dataset="synthetic", mode="fast", lang="en", n_samples=3, tp=4, fp=1, fn=2)
    r.per_type = {
        "person": TypeMetrics(tp=3, fp=1, fn=2),
        "email": TypeMetrics(tp=1, fp=0, fn=0),
    }
    r.elapsed_s = 0.5
    return r


def test_payload_has_package_version_string():
    payload = build_payload("synthetic", [_fast_result()])
    assert payload["package_version_string"] == __version__


def test_payload_modes_include_per_type():
    payload = build_payload("synthetic", [_fast_result()])
    fast = payload["modes"]["fast"]
    # legacy overall fields retained (backward compat)
    assert {"precision", "recall", "f1"} <= set(fast)
    # enriched per-type block
    assert "per_type" in fast
    person = fast["per_type"]["person"]
    assert set(person) == {"precision", "recall", "f1", "tp", "fp", "fn"}
    assert person["tp"] == 3 and person["fp"] == 1 and person["fn"] == 2


def test_payload_exposes_flat_per_type_mode():
    # The en precision-floor test reads data["per_type_fast"]["person"].
    payload = build_payload("synthetic", [_fast_result()])
    assert "per_type_fast" in payload
    assert payload["per_type_fast"]["person"]["tp"] == 3


def test_payload_keeps_legacy_top_level_fields():
    payload = build_payload("synthetic", [_fast_result()])
    assert payload["dataset"] == "synthetic"
    assert payload["language"] == "en"
    assert payload["samples"] == 3
    assert "version" in payload and "date" in payload
