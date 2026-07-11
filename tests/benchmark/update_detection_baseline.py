"""Refresh the committed FAST-mode detection recall/precision baseline.

FAST-mode detection is deterministic (pure regex/validators, no NER, no
randomness), so recall/precision on the fixed pii_bench_zh seed=42 corpus is
exactly reproducible. This script recomputes those numbers and rewrites
tests/benchmark/detection_baseline.json — run it ONLY after an intentional
detection change, then review + commit the diff.

Usage:
    PYTHONPATH=src python tests/benchmark/update_detection_baseline.py
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

from tests.benchmark.evaluator import evaluate
from tests.benchmark.generators.zh import generate
from tests.benchmark.model import Entity, Sample

_BASELINE_PATH = Path(__file__).parent / "detection_baseline.json"


def main() -> None:
    spec = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))

    raw = generate(count=spec["count"], seed=spec["seed"])
    samples = [
        Sample(
            text=s["text"],
            lang=s["lang"],
            entities=[
                Entity(text=e["text"], type=e["type"], start=e["start"], end=e["end"])
                for e in s["entities"]
            ],
        )
        for s in raw
    ]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = evaluate(
            samples,
            mode=spec["mode"],
            match=spec["match"],
            dataset_name="pii_bench_zh",
        )

    spec["measurements"] = {
        "recall": round(result.recall, 4),
        "precision": round(result.precision, 4),
    }
    _BASELINE_PATH.write_text(
        json.dumps(spec, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"Detection baseline updated: recall={spec['measurements']['recall']} "
        f"precision={spec['measurements']['precision']} "
        f"(pii_bench_zh seed={spec['seed']} N={spec['count']}, mode={spec['mode']}). "
        "Review and commit tests/benchmark/detection_baseline.json"
    )


if __name__ == "__main__":
    main()
