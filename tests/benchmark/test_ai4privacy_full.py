"""Full three-layer benchmark against ai4privacy/pii-masking-400k.

Compares: fast (regex) vs ner (regex+NER) vs auto (regex+NER+Ollama)
Run with: pytest tests/benchmark/test_ai4privacy_full.py -v -s -m slow --timeout=600
"""

import importlib.util
import time

import pytest

HAS_DATASETS = importlib.util.find_spec("datasets") is not None

pytestmark = pytest.mark.slow

LABEL_MAP = {
    "EMAIL": "email",
    "TEL": "phone",
    "SOCIALNUMBER": "ssn",
    "IDCARD": "id_number",
    "PASSPORT": "passport",
    "POSTCODE": "postcode",
    "CREDITCARDNUMBER": "credit_card",
    "GIVENNAME1": "person",
    "LASTNAME1": "person",
    "LASTNAME2": "person",
    "STREET": "address",
    "CITY": "location",
    "STATE": "location",
    "IP": "ip_address",
}

DETECTABLE_LABELS = set(LABEL_MAP.keys())


def _run_benchmark(mode, n_examples=200):
    from datasets import load_dataset

    from argus_redact import redact

    ds = load_dataset(
        "ai4privacy/pii-masking-400k",
        split="train",
        streaming=True,
    )

    tp, fp, fn = 0, 0, 0
    t_start = time.perf_counter()

    for i, ex in enumerate(ds):
        if i >= n_examples:
            break

        text = ex["source_text"]

        expected_pii = set()
        for span in ex.get("privacy_mask", []):
            if span["label"] in DETECTABLE_LABELS:
                expected_pii.add(span["value"])

        redacted, key = redact(text, mode=mode, lang="en", seed=42)
        detected_pii = set(key.values())

        hits = expected_pii & detected_pii
        misses = expected_pii - detected_pii
        false_alarms = detected_pii - expected_pii

        tp += len(hits)
        fn += len(misses)
        fp += len(false_alarms)

    elapsed = time.perf_counter() - t_start
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "mode": mode,
        "n": n_examples,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "elapsed_s": elapsed,
        "docs_per_sec": n_examples / elapsed if elapsed > 0 else 0,
    }


def _print_result(r):
    print(
        f"  {r['mode']:6s}  P={r['precision']:5.1%}  R={r['recall']:5.1%}"
        f"  F1={r['f1']:5.1%}  TP={r['tp']}  FP={r['fp']}  FN={r['fn']}"
        f"  {r['elapsed_s']:.1f}s  {r['docs_per_sec']:.0f} docs/s"
    )


class TestThreeLayerComparison:
    @pytest.fixture(scope="class")
    def results(self):
        if not HAS_DATASETS:
            pytest.skip("datasets not installed")
        return {}

    def test_layer1_regex_only(self, results):
        r = _run_benchmark("fast", n_examples=200)
        results["fast"] = r
        print("\n=== ai4privacy benchmark (200 examples) ===")
        _print_result(r)

    def test_layer1_plus_2_ner(self, results):
        r = _run_benchmark("ner", n_examples=200)
        results["ner"] = r
        _print_result(r)

    def test_comparison_summary(self, results):
        if "fast" not in results or "ner" not in results:
            pytest.skip("previous tests didn't run")

        print("\n=== Comparison ===")
        print(f"  {'Mode':6s}  {'Precision':>9s}  {'Recall':>8s}  {'F1':>7s}  {'Speed':>10s}")
        for mode in ["fast", "ner"]:
            r = results[mode]
            print(
                f"  {mode:6s}  {r['precision']:>8.1%}  {r['recall']:>7.1%}"
                f"  {r['f1']:>6.1%}  {r['docs_per_sec']:>7.0f} d/s"
            )

        fast = results["fast"]
        ner = results["ner"]
        print(
            f"\n  NER improvement: recall +{ner['recall'] - fast['recall']:.1%}"
            f", F1 +{ner['f1'] - fast['f1']:.1%}"
        )
