"""Report formatting — terminal table, JSON, markdown."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .model import Result


def print_report(result: Result) -> None:
    """Print evaluation result to terminal."""
    print(f"\n{'=' * 60}")
    print(f"  Dataset:   {result.dataset}")
    print(f"  Mode:      {result.mode}")
    print(f"  Language:  {result.lang}")
    print(f"  Samples:   {result.n_samples}")
    print(f"  Time:      {result.elapsed_s:.1f}s ({result.docs_per_sec:.0f} docs/s)")
    print(f"{'=' * 60}")
    print(f"  Precision: {result.precision:.2%}")
    print(f"  Recall:    {result.recall:.2%}")
    print(f"  F1:        {result.f1:.2%}")
    print(f"  TP={result.tp}  FP={result.fp}  FN={result.fn}")
    print(f"{'-' * 60}")

    if result.per_type:
        print(
            f"  {'Type':<15s} {'Prec':>7s} {'Recall':>7s} {'F1':>7s}  {'TP':>4s} {'FP':>4s} {'FN':>4s}"
        )
        for etype, m in sorted(result.per_type.items()):
            print(
                f"  {etype:<15s} {m.precision:>6.1%} {m.recall:>6.1%} {m.f1:>6.1%}"
                f"  {m.tp:>4d} {m.fp:>4d} {m.fn:>4d}"
            )
    print()


def print_comparison(results: list[Result]) -> None:
    """Print side-by-side comparison of multiple runs."""
    print(f"\n{'=' * 70}")
    print(f"  {'Dataset':<16s} {'Mode':<6s} {'Prec':>7s} {'Recall':>7s} {'F1':>7s} {'Speed':>10s}")
    print(f"{'-' * 70}")
    for r in results:
        print(
            f"  {r.dataset:<16s} {r.mode:<6s} {r.precision:>6.1%} {r.recall:>6.1%}"
            f" {r.f1:>6.1%} {r.docs_per_sec:>7.0f} d/s"
        )
    print()


def save_result(result: Result, results_dir: Path) -> Path:
    """Save result as JSON snapshot."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{result.dataset}_{result.mode}_{ts}.json"
    path = results_dir / filename

    data = result.to_dict()
    data["timestamp"] = ts

    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    print(f"  Saved: {path}")
    return path
