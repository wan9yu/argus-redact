"""CLI entry point: python -m benchmarks [dataset] [options]

Examples:
    python -m benchmarks ai4privacy --lang en --mode fast --limit 500
    python -m benchmarks ai4privacy --mode fast,ner --limit 200
    python -m benchmarks all --mode fast --limit 1000
    python -m benchmarks list
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .adapters import get_adapter, list_adapters
from .evaluator import evaluate
from .report import print_comparison, print_report, save_result

RESULTS_DIR = Path(__file__).parent / "results"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="benchmarks",
        description="Evaluate argus-redact against public PII datasets.",
    )
    parser.add_argument(
        "dataset",
        help="Dataset name (or 'all' / 'list')",
    )
    parser.add_argument("--lang", default=None, help="Filter by language code")
    parser.add_argument("--mode", default="fast", help="Detection mode(s), comma-separated")
    parser.add_argument("--limit", type=int, default=1000, help="Max samples per dataset")
    parser.add_argument("--match", choices=["value", "span"], default="value", help="Matching strategy")
    parser.add_argument("--save", action="store_true", help="Save results to JSON")

    args = parser.parse_args(argv)

    if args.dataset == "list":
        print("Available datasets:")
        for name in list_adapters():
            print(f"  - {name}")
        return

    modes = [m.strip() for m in args.mode.split(",")]

    if args.dataset == "all":
        dataset_names = list_adapters()
    else:
        dataset_names = [args.dataset]

    all_results = []

    for ds_name in dataset_names:
        adapter = get_adapter(ds_name)

        # Check language support
        if args.lang and args.lang not in adapter.languages:
            print(
                f"Warning: {ds_name} does not list '{args.lang}' "
                f"(available: {', '.join(adapter.languages)}). Skipping.",
                file=sys.stderr,
            )
            continue

        for mode in modes:
            samples = adapter.load(lang=args.lang, limit=args.limit)
            result = evaluate(
                samples,
                mode=mode,
                match=args.match,
                dataset_name=ds_name,
            )
            print_report(result)
            all_results.append(result)

            if args.save:
                save_result(result, RESULTS_DIR)

    if len(all_results) > 1:
        print_comparison(all_results)


if __name__ == "__main__":
    main()
