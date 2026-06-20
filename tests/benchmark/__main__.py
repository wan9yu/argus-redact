"""CLI entry point: python -m tests.benchmark [dataset] [options]

Examples:
    python -m tests.benchmark ai4privacy --lang en --mode fast --limit 500
    python -m tests.benchmark ai4privacy --mode fast,ner --limit 200
    python -m tests.benchmark all --mode fast --limit 1000
    python -m tests.benchmark list
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

from argus_redact import __version__

from .adapters import get_adapter, list_adapters
from .evaluator import evaluate
from .report import print_comparison, print_report

RESULTS_DIR = Path(__file__).parent / "results"


def _per_type_dict(result) -> dict:
    """Per-type {precision,recall,f1 (as %), tp,fp,fn} for one Result.

    Percentages match the overall mode block (1-decimal %), so a reader can
    compare a per-type row against the overall row without unit conversion.
    """
    return {
        etype: {
            "precision": round(m.precision * 100, 1),
            "recall": round(m.recall * 100, 1),
            "f1": round(m.f1 * 100, 1),
            "tp": m.tp,
            "fp": m.fp,
            "fn": m.fn,
        }
        for etype, m in sorted(result.per_type.items())
    }


def build_payload(ds_name: str, ds_results: list) -> dict:
    """Build the saved-result JSON for one dataset's runs (one per mode).

    Shape (backward-compatible — only adds keys):
      * top-level ``version`` (human label) + ``package_version_string``
        (``argus_redact.__version__``, what the build self-reports)
      * ``modes[mode]`` keeps the overall ``precision/recall/f1`` AND gains a
        ``per_type`` block (per-type {precision,recall,f1,tp,fp,fn})
      * ``per_type_{mode}`` — the same per-type block flattened to the top level
        (the form the en precision-floor test reads as ``per_type_fast``)
    """
    first = ds_results[0]
    modes: dict = {}
    per_type_flat: dict = {}
    for r in ds_results:
        per_type = _per_type_dict(r)
        modes[r.mode] = {
            "precision": round(r.precision * 100, 1),
            "recall": round(r.recall * 100, 1),
            "f1": round(r.f1 * 100, 1),
            "per_type": per_type,
        }
        per_type_flat[f"per_type_{r.mode}"] = per_type
    return {
        "version": __version__,
        "package_version_string": __version__,
        "dataset": ds_name,
        "language": first.lang,
        "samples": first.n_samples,
        "modes": modes,
        **per_type_flat,
        "date": datetime.date.today().isoformat(),
    }


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
    parser.add_argument(
        "--match", choices=["value", "span"], default="value", help="Matching strategy"
    )
    parser.add_argument(
        "--save",
        type=str,
        metavar="PATH",
        help="Write benchmark result JSON to PATH. Schema: see tests/benchmark/results/README.md.",
    )

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

        ds_results: list = []
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
            ds_results.append(result)

        if args.save and ds_results:
            payload = build_payload(ds_name, ds_results)
            save_path = Path(args.save)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            save_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"  Saved: {save_path}")

    if len(all_results) > 1:
        print_comparison(all_results)


if __name__ == "__main__":
    main()
