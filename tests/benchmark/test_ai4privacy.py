"""Benchmark against ai4privacy/pii-masking-400k dataset.

Run with: pytest tests/benchmark/test_ai4privacy.py -v -s --timeout=300
Requires: pip install datasets
"""

import importlib.util

import pytest

HAS_DATASETS = importlib.util.find_spec("datasets") is not None

pytestmark = pytest.mark.slow


# Map ai4privacy labels to argus-redact types
LABEL_MAP = {
    "EMAIL": "email",
    "TEL": "phone",
    "SOCIALNUMBER": "ssn",
    "IDCARD": "id_number",
    "PASSPORT": "passport",
    "POSTCODE": "postcode",
    "IP": "ip_address",
    "CREDITCARDNUMBER": "credit_card",
}

# Labels we CAN detect with regex
DETECTABLE_LABELS = set(LABEL_MAP.keys())


@pytest.fixture(scope="module")
def benchmark_results():
    if not HAS_DATASETS:
        pytest.skip("datasets not installed")

    from argus_redact.lang.de.patterns import PATTERNS as DE
    from argus_redact.lang.en.patterns import PATTERNS as EN
    from argus_redact.lang.in_.patterns import PATTERNS as IN
    from argus_redact.lang.shared.patterns import PATTERNS as SHARED
    from argus_redact.lang.uk.patterns import PATTERNS as UK
    from argus_redact.pure.patterns import match_patterns
    from datasets import load_dataset

    patterns = EN + DE + UK + IN + SHARED

    ds = load_dataset(
        "ai4privacy/pii-masking-400k",
        split="train",
        streaming=True,
    )

    tp, fp, fn = 0, 0, 0
    per_type = {}
    n_examples = 0
    max_examples = 1000

    for ex in ds:
        if n_examples >= max_examples:
            break
        n_examples += 1

        text = ex["source_text"]
        expected = set()
        for span in ex.get("privacy_mask", []):
            if span["label"] in DETECTABLE_LABELS:
                expected.add((span["value"], LABEL_MAP[span["label"]]))

        detected = set()
        for r in match_patterns(text, patterns)[0]:
            detected.add((r.text, r.type))

        # Only evaluate on types we claim to detect
        expected_types = {t for _, t in expected}
        detected_filtered = {(text, t) for text, t in detected if t in expected_types}

        hits = expected & detected_filtered
        misses = expected - detected_filtered
        false_alarms = detected_filtered - expected

        tp += len(hits)
        fn += len(misses)
        fp += len(false_alarms)

        for _, etype in hits:
            per_type.setdefault(etype, {"tp": 0, "fp": 0, "fn": 0})
            per_type[etype]["tp"] += 1
        for _, etype in misses:
            per_type.setdefault(etype, {"tp": 0, "fp": 0, "fn": 0})
            per_type[etype]["fn"] += 1
        for _, etype in false_alarms:
            per_type.setdefault(etype, {"tp": 0, "fp": 0, "fn": 0})
            per_type[etype]["fp"] += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "n_examples": n_examples,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "per_type": per_type,
    }


class TestAi4PrivacyBenchmark:
    def test_should_report_results(self, benchmark_results):
        r = benchmark_results
        print(f"\n=== ai4privacy/pii-masking-400k (first {r['n_examples']} examples) ===")
        print(f"  Precision: {r['precision']:.2%}")
        print(f"  Recall:    {r['recall']:.2%}")
        print(f"  F1:        {r['f1']:.2%}")
        print(f"  TP={r['tp']} FP={r['fp']} FN={r['fn']}")
        for etype, c in r["per_type"].items():
            total_p = c["tp"] + c["fp"]
            total_r = c["tp"] + c["fn"]
            p = c["tp"] / total_p if total_p > 0 else 1.0
            rec = c["tp"] / total_r if total_r > 0 else 1.0
            print(
                f"  {etype:15s} P={p:.0%} R={rec:.0%}" f" (TP={c['tp']} FP={c['fp']} FN={c['fn']})"
            )

    def test_should_achieve_reasonable_f1(self, benchmark_results):
        assert benchmark_results["f1"] >= 0.1, f"F1 too low: {benchmark_results['f1']:.2%}"
