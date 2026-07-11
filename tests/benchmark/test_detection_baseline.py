"""Committed-baseline drift gate for FAST-mode detection recall/precision.

A silent detection-recall drop is a silent PII leak. Latency already has a
committed-baseline drift gate (tests/benchmark/baseline.json + compare_baseline.py
in CI/perf.yml); this is the same machinery for the core safety metric.

Why it can be a TIGHT floor (not a loose ±10%): FAST-mode detection is
DETERMINISTIC — pure regex/validators, no NER model, no randomness — so recall on
a FIXED corpus is exactly reproducible run-to-run. The corpus is the pii_bench_zh
generator (seed=42), pure Python with NO network dependency, so it runs in the
normal `-m "not ner and not semantic"` CI. The gate only moves when detection
code changes; it never flakes.

Refresh the baseline (after an intentional detection change) with:
    make detection-update
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

from tests.benchmark.evaluator import evaluate
from tests.benchmark.generators.zh import generate
from tests.benchmark.model import Entity, Result, Sample

_BASELINE_PATH = Path(__file__).parent / "detection_baseline.json"

# Deterministic corpus is exactly reproducible, so the floor can be tight. This
# only absorbs float-rounding at the 4th decimal; a real detection drop is far
# larger and is caught.
_TOLERANCE = 0.005


def _load_baseline() -> dict:
    return json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))


def _measure(spec: dict) -> Result:
    """Regenerate the deterministic corpus and run FAST-mode detection.

    No network: the pii_bench_zh generator is pure Python (seed-driven fakers).
    """
    raw = generate(count=spec["count"], seed=spec["seed"])
    samples = [
        Sample(
            text=s["text"],
            lang=s["lang"],
            entities=[
                Entity(
                    text=e["text"],
                    type=e["type"],
                    start=e["start"],
                    end=e["end"],
                )
                for e in s["entities"]
            ],
        )
        for s in raw
    ]
    with warnings.catch_warnings():
        # The evaluator uses salt=42 (an int) purely for reproducibility; that
        # trips the low-entropy-salt SecurityWarning, which is irrelevant here.
        warnings.simplefilter("ignore")
        return evaluate(
            samples,
            mode=spec["mode"],
            match=spec["match"],
            dataset_name="pii_bench_zh",
        )


def test_fast_detection_recall_precision_no_regression():
    spec = _load_baseline()
    base = spec["measurements"]
    result = _measure(spec)

    recall_floor = base["recall"] - _TOLERANCE
    precision_floor = base["precision"] - _TOLERANCE

    assert result.recall >= recall_floor, (
        "recall regression = silent PII leak: "
        f"fast-mode recall {result.recall:.4f} dropped below baseline "
        f"{base['recall']:.4f} (floor {recall_floor:.4f}) on the pii_bench_zh "
        f"seed={spec['seed']} corpus (N={spec['count']}). "
        "If this drop is intentional, run `make detection-update` and commit "
        "tests/benchmark/detection_baseline.json."
    )

    assert result.precision >= precision_floor, (
        "precision regression: fast-mode precision "
        f"{result.precision:.4f} dropped below baseline {base['precision']:.4f} "
        f"(floor {precision_floor:.4f}) on the pii_bench_zh seed={spec['seed']} "
        f"corpus (N={spec['count']}). "
        "If intentional, run `make detection-update` and commit "
        "tests/benchmark/detection_baseline.json."
    )
