"""Benchmark tests — measure precision/recall of PII detection.

Runs regex-only (mode='fast') against labeled benchmark data.
Reports precision, recall, F1 per PII type and overall.
"""

import json
from pathlib import Path

from argus_redact.pure.patterns import match_patterns

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _load_benchmark(filename):
    with open(FIXTURES_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


def _run_benchmark(examples, patterns):
    """Run patterns against labeled examples, compute precision/recall."""
    tp, fp, fn = 0, 0, 0
    per_type: dict[str, dict[str, int]] = {}

    for ex in examples:
        expected = {(e["text"], e["type"]) for e in ex["entities"]}
        detected = {(r.text, r.type) for r in match_patterns(ex["input"], patterns)[0]}

        hits = expected & detected
        misses = expected - detected
        false_alarms = detected - expected

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
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "per_type": per_type,
    }


def _print_report(title, result):
    print(f"\n=== {title} ===")
    print(f"  Precision: {result['precision']:.2%}")
    print(f"  Recall:    {result['recall']:.2%}")
    print(f"  F1:        {result['f1']:.2%}")
    print(f"  TP={result['tp']} FP={result['fp']} FN={result['fn']}")
    for etype, c in result["per_type"].items():
        total_p = c["tp"] + c["fp"]
        total_r = c["tp"] + c["fn"]
        p = c["tp"] / total_p if total_p > 0 else 1.0
        r = c["tp"] / total_r if total_r > 0 else 1.0
        print(f"  {etype:15s} P={p:.0%} R={r:.0%} (TP={c['tp']} FP={c['fp']} FN={c['fn']})")


class TestBenchmarkChinese:
    def test_should_achieve_high_recall_on_zh_regex(self):
        from argus_redact.lang.shared.patterns import PATTERNS as SHARED
        from argus_redact.lang.zh.patterns import PATTERNS as ZH

        examples = _load_benchmark("benchmark_zh.json")
        result = _run_benchmark(examples, ZH + SHARED)

        _print_report("Chinese Benchmark (regex)", result)

        assert result["recall"] >= 0.8, f"Recall too low: {result['recall']:.2%}"
        assert result["precision"] >= 0.8, f"Precision too low: {result['precision']:.2%}"

    def test_should_have_zero_false_negatives_on_phone(self):
        from argus_redact.lang.shared.patterns import PATTERNS as SHARED
        from argus_redact.lang.zh.patterns import PATTERNS as ZH

        examples = _load_benchmark("benchmark_zh.json")
        result = _run_benchmark(examples, ZH + SHARED)

        phone = result["per_type"].get("phone", {"fn": 0})
        assert phone["fn"] == 0, f"Missed {phone['fn']} phone numbers"


class TestBenchmarkEnglish:
    def test_should_achieve_high_recall_on_en_regex(self):
        from argus_redact.lang.en.patterns import PATTERNS as EN
        from argus_redact.lang.shared.patterns import PATTERNS as SHARED

        examples = _load_benchmark("benchmark_en.json")
        result = _run_benchmark(examples, EN + SHARED)

        _print_report("English Benchmark (regex)", result)

        assert result["recall"] >= 0.8, f"Recall too low: {result['recall']:.2%}"
        assert result["precision"] >= 0.8, f"Precision too low: {result['precision']:.2%}"
