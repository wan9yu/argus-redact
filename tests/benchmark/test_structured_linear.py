"""Per-cell cost of structured redaction must be flat in the cell count N.

The stateless per-cell path re-threaded the whole accumulation key into (and out
of) the Rust ``replace`` on every cell, re-cloning/rebuilding it each time —
O(|key|) per cell, hence O(N^2) over a document of N cells each carrying a fresh
distinct value. A session that keeps the key in Rust across cells makes per-cell
cost flat.

This test builds CSVs of N = 100 / 400 / 1600 cells, each cell a DISTINCT phone
(so the key grows to N entries), and asserts the amortized per-cell wall time at
N = 1600 is not more than 2x the per-cell wall time at N = 100. Under the old
O(N^2) behaviour the per-cell time grows ~linearly in N (roughly 16x here), so
this FAILS pre-refactor and PASSES after.

Marked ``slow`` so the default gate skips it; run explicitly with ``-m slow``.
"""

import time
import warnings

import pytest

from argus_redact.structured import redact_csv

pytestmark = pytest.mark.slow


def _distinct_phone_csv(n: int) -> str:
    """A headerless-friendly CSV of ``n`` cells (one per row), each a distinct
    valid CN mobile number so every cell mints a new key entry."""
    # 138 + 8 digits keeps 11-digit length and stays distinct for n < 1e8.
    rows = [f"1{38_000_000_00 + i}" for i in range(n)]
    return "col\n" + "\n".join(rows)


def _per_cell_seconds(n: int, repeats: int = 3) -> float:
    """Best-of-``repeats`` amortized per-cell wall time for redacting ``n`` cells."""
    csv_text = _distinct_phone_csv(n)
    best = float("inf")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for _ in range(repeats):
            t0 = time.perf_counter()
            redacted, key = redact_csv(csv_text, mode="fast", salt=42, has_header=True)
            elapsed = time.perf_counter() - t0
            best = min(best, elapsed)
        # Non-vacuity: the key really did grow to n distinct entries.
        assert len(key) == n, f"expected {n} key entries, got {len(key)}"
    return best / n


def test_per_cell_cost_is_flat_in_n():
    # Warm up (first call pays import/JIT-ish costs) before timing.
    _per_cell_seconds(100)

    per_cell_small = _per_cell_seconds(100)
    per_cell_large = _per_cell_seconds(1600)

    # A linear (flat per-cell) implementation keeps this ratio near 1; the old
    # quadratic path pushes it toward ~16. 2x leaves generous headroom for noise
    # while still failing hard on O(N^2).
    ratio = per_cell_large / per_cell_small
    assert ratio < 2.0, (
        f"per-cell time grew superlinearly: N=100 -> {per_cell_small * 1e6:.1f}us/cell, "
        f"N=1600 -> {per_cell_large * 1e6:.1f}us/cell (ratio {ratio:.1f}x, want < 2x). "
        "The accumulation key is being re-cloned/re-marshalled per cell."
    )


def test_intermediate_size_confirms_scaling():
    # A third point (N=400) guards against a fluke at the endpoints: the per-cell
    # time at 400 must also stay within 2x of the N=100 baseline.
    _per_cell_seconds(100)
    per_cell_small = _per_cell_seconds(100)
    per_cell_mid = _per_cell_seconds(400)
    ratio = per_cell_mid / per_cell_small
    assert ratio < 2.0, f"per-cell time at N=400 is {ratio:.1f}x the N=100 baseline (want < 2x)"
