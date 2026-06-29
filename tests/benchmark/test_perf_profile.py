"""Structural smoke test for the full-distribution perf profiler.

Not a timing assertion (values are machine-dependent) — it verifies the profile
emits every percentile field the paper table needs and that the distribution is
internally ordered (min <= p50 <= p99 <= max).
"""

import sys
from pathlib import Path

_BENCH = Path(__file__).resolve().parent
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import perf_profile  # noqa: E402

_DIST_KEYS = {
    "min_ms",
    "p50_ms",
    "p90_ms",
    "p95_ms",
    "p99_ms",
    "max_ms",
    "mean_ms",
    "stdev_ms",
    "docs_per_s",
}


def test_profile_emits_full_distribution():
    workloads = perf_profile.profile(iterations=3, warmup=1)
    assert {"en_1kb", "zh_1kb"} <= set(workloads)
    for label, w in workloads.items():
        assert w["lang"] in ("en", "zh"), label
        assert w["bytes"] > 0, label
        for part in ("redact_fast", "detect_l1"):
            stats = w[part]
            assert _DIST_KEYS <= set(stats), (label, part, set(stats))
            assert stats["min_ms"] <= stats["p50_ms"] <= stats["p99_ms"] <= stats["max_ms"], (
                label,
                part,
                stats,
            )
            assert stats["docs_per_s"] > 0, (label, part)
