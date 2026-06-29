"""Full-distribution performance profile — the reproducible source for the paper perf table.

`run_perf_budget.py` is the CI regression gate (5-run median, ±10% threshold).
This is its paper-facing companion: it captures the FULL latency distribution
(min / p50 / p90 / p95 / p99 / max / mean / stdev) plus throughput (docs/s) for
end-to-end ``redact(mode="fast")`` and raw ``_core.detect_l1``, per corpus, with
byte count and language. It reuses the same throughput corpora as
``bench_l1_rust_vs_python`` so the numbers line up across the perf artifacts.

Usage:
    python tests/benchmark/perf_profile.py --output tests/benchmark/results/perf_profile_0.7.16.json
    python tests/benchmark/perf_profile.py --output ... --iterations 500
        --platform "Apple M1 Max" --commit abc1234
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

_REPO_SRC = str(Path(__file__).resolve().parent.parent.parent / "src")
if _REPO_SRC not in sys.path:
    sys.path.insert(0, _REPO_SRC)

# Reuse the canonical throughput corpora + fixed salt — no third copy of the corpus.
from bench_l1_rust_vs_python import _BENCH_SALT, _THROUGHPUT_CORPUS  # noqa: E402


def _distribution(fn, *, iterations: int, warmup: int = 20) -> dict:
    """Full latency distribution (ms) over `iterations` calls after `warmup`."""
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    samples.sort()
    n = len(samples)

    def _pct(p: float) -> float:
        # nearest-rank on the sorted sample
        return samples[min(n - 1, int(round(p / 100.0 * (n - 1))))]

    median = statistics.median(samples)
    return {
        "min_ms": round(samples[0], 5),
        "p50_ms": round(median, 5),
        "p90_ms": round(_pct(90), 5),
        "p95_ms": round(_pct(95), 5),
        "p99_ms": round(_pct(99), 5),
        "max_ms": round(samples[-1], 5),
        "mean_ms": round(statistics.fmean(samples), 5),
        "stdev_ms": round(statistics.pstdev(samples), 5),
        "docs_per_s": round(1000.0 / median, 1) if median > 0 else None,
    }


def profile(*, iterations: int = 300, warmup: int = 20) -> dict:
    """Run the full-distribution profile over every throughput corpus."""
    from argus_redact import redact
    from argus_redact._core_loader import _core

    redact("warm-up", salt=_BENCH_SALT)  # warm caches/imports

    workloads: dict[str, dict] = {}
    for label, (lang, text) in _THROUGHPUT_CORPUS.items():

        def _redact(t=text, lng=lang):
            return redact(t, salt=_BENCH_SALT, mode="fast", lang=lng)

        def _detect(t=text, lng=lang):
            return _core.detect_l1(t, [lng], [])

        workloads[label] = {
            "lang": lang,
            "bytes": len(text.encode("utf-8")),
            "redact_fast": _distribution(_redact, iterations=iterations, warmup=warmup),
            "detect_l1": _distribution(_detect, iterations=iterations, warmup=warmup),
        }
    return workloads


def main() -> None:
    ap = argparse.ArgumentParser(description="Full-distribution perf profile (paper perf table).")
    ap.add_argument("--output", required=True)
    ap.add_argument("--iterations", type=int, default=300)
    ap.add_argument("--platform", default=None)
    ap.add_argument("--commit", default="unknown")
    args = ap.parse_args()

    import argus_redact

    workloads = profile(iterations=args.iterations)
    out = {
        "schema_version": 1,
        "benchmark": "perf_profile",
        "package_version": argus_redact.__version__,
        "platform": args.platform or platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "commit": args.commit,
        "iterations": args.iterations,
        "workloads": workloads,
    }
    Path(args.output).write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    for label, w in workloads.items():
        r, d = w["redact_fast"], w["detect_l1"]
        print(
            f"{label:10s} {w['bytes']:6d}B  "
            f"redact p50 {r['p50_ms']:.3f} p99 {r['p99_ms']:.3f} ({r['docs_per_s']:.0f} d/s)  "
            f"detect_l1 p50 {d['p50_ms']:.3f} p99 {d['p99_ms']:.3f}"
        )


if __name__ == "__main__":
    main()
