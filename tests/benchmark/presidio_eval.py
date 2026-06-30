"""Presidio head-to-head benchmark — Microsoft Presidio on argus's own terms.

Runs Microsoft Presidio against the SAME datasets, SAME gold labels, SAME
value/span matching, and the SAME per-sample scoring as argus-redact, so the
paper's §9.4 can put argus's F1 next to Presidio's. Only the *detector* changes:
Presidio's default out-of-the-box recognizers replace argus's detection layers.

Fairness contract (do not deviate):
  * Same datasets, via the unchanged ``tests/benchmark/adapters`` (same gold as
    argus).
  * Same scoring as ``evaluator.evaluate`` — this module reuses ``_match_value``
    / ``_match_span`` and replicates the per-sample accumulation verbatim,
    INCLUDING the value-match fairness rule: a detection of a type the dataset
    does NOT label is ignored, never counted as a false positive. Presidio is
    judged on the same label set, per dataset, as argus.
  * Default recognizers only — ``AnalyzerEngine()`` with no custom config. We do
    NOT cripple Presidio, and we do NOT silently give it a zh model.

en-engine-on-zh: Presidio out-of-the-box ships only an English NLP engine, so zh
text is analyzed with the en engine (``ENGINE_LANG = "en"`` always). Its
language-agnostic regex recognizers (email / credit-card / IP, phonenumbers)
still fire; its spaCy NER does not. This IS the honest out-of-box zh result —
custom zh recognizers would improve it, but adding them would not be "out of the
box". The caveat is recorded in the output ``engine`` block.

Output JSON mirrors the argus ``<dataset>_<version>.json`` shape field-for-field
(one ``modes`` key, ``presidio``) plus an ``engine`` block, so the two files line
up for a side-by-side comparison.

Run (the controller runs the full datasets; these are the documented invocations):
    python tests/benchmark/presidio_eval.py ai4privacy --lang en --limit 500 --save PATH
    python tests/benchmark/presidio_eval.py pii_bench_zh --limit 1000 --save PATH
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

# Run-as-a-script support: when invoked as ``python tests/benchmark/presidio_eval.py``
# the repo root is not on sys.path, so the absolute ``tests.benchmark.*`` imports
# (which the adapters themselves use) would fail. Insert it before importing.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from argus_redact import __version__ as ARGUS_VERSION  # noqa: E402
from tests.benchmark.__main__ import _by_class_dict, _per_type_dict  # noqa: E402
from tests.benchmark.adapters import get_adapter, list_adapters  # noqa: E402
from tests.benchmark.evaluator import _match_span, _match_value  # noqa: E402
from tests.benchmark.model import Entity, Result, TypeMetrics  # noqa: E402
from tests.benchmark.report import print_report  # noqa: E402

# Presidio ships only an English NLP engine out of the box; always analyze with it.
ENGINE_LANG = "en"

ENGINE_NOTE = (
    "out-of-box default recognizers; zh analyzed with the en engine so only "
    "language-agnostic regex recognizers fire — custom zh recognizers would improve it"
)

# Presidio entity type -> argus canonical type. Results whose type is absent here
# are dropped (they cannot match any gold type the adapters emit anyway).
PRESIDIO_TO_CANONICAL = {
    "PERSON": "person",
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "US_SSN": "ssn",
    "CREDIT_CARD": "credit_card",
    "IP_ADDRESS": "ip_address",
    "LOCATION": "location",
    "URL": "url",
    "US_PASSPORT": "passport",
    "DATE_TIME": "date",
}


def build_analyzer():
    """Build the default out-of-the-box ``AnalyzerEngine`` (import lazily)."""
    from presidio_analyzer import AnalyzerEngine

    return AnalyzerEngine()


def _spacy_model_name(analyzer) -> str:
    """The spaCy model Presidio actually loaded for ``ENGINE_LANG`` (or 'unknown')."""
    nlp = getattr(analyzer, "nlp_engine", None)
    models = getattr(nlp, "models", None) or []
    for m in models:
        if isinstance(m, dict) and m.get("lang_code") == ENGINE_LANG:
            return m.get("model_name", "unknown")
    return "unknown"


def _presidio_version() -> str:
    try:
        return version("presidio-analyzer")
    except PackageNotFoundError:
        return "unknown"


def engine_block(analyzer) -> dict:
    """The ``engine`` provenance block recorded in the output JSON."""
    return {
        "engine": "presidio",
        "presidio_version": _presidio_version(),
        "nlp_engine_lang": ENGINE_LANG,
        "spacy_model": _spacy_model_name(analyzer),
        "note": ENGINE_NOTE,
    }


def detect_entities(analyzer, text: str) -> list[Entity]:
    """Run Presidio once on ``text`` and map results to canonical argus entities."""
    results = analyzer.analyze(text=text, language=ENGINE_LANG, entities=None)
    detected: list[Entity] = []
    for r in results:
        canonical = PRESIDIO_TO_CANONICAL.get(r.entity_type)
        if canonical is None:
            continue
        detected.append(
            Entity(text=text[r.start : r.end], type=canonical, start=r.start, end=r.end)
        )
    return detected


def evaluate_presidio(
    samples,
    analyzer,
    *,
    match: str = "value",
    tolerance: int = 3,
    dataset_name: str = "unknown",
) -> Result:
    """Score Presidio against labeled samples using argus's exact evaluator logic.

    The body mirrors ``evaluator.evaluate`` per sample (same matching, same
    accumulation, same value-match fairness filter) — only the detector differs:
    Presidio replaces the ``redact`` call.
    """
    result = Result(dataset=dataset_name, mode="presidio", lang="", n_samples=0)
    langs_seen: set[str] = set()

    t_start = time.perf_counter()

    for sample in samples:
        result.n_samples += 1
        langs_seen.add(sample.lang)

        detected_entities = detect_entities(analyzer, sample.text)

        if match == "span" and all(e.start is not None for e in sample.entities):
            hits_list, misses_list, fa_list = _match_span(
                sample.entities,
                detected_entities,
                tolerance,
            )
            hits_typed = [(e.text, e.type) for e in hits_list]
            misses_typed = [(e.text, e.type) for e in misses_list]
            fa_typed = [(e.text, e.type) for e in fa_list]
        else:
            expected_set = {(e.text, e.type) for e in sample.entities}
            detected_set = {(e.text, e.type) for e in detected_entities}
            # Only evaluate types present in expected — a detection of a type the
            # dataset does not label is ignored, never an FP (the fairness rule).
            expected_types = {t for _, t in expected_set}
            detected_filtered = {(t, tp) for t, tp in detected_set if tp in expected_types}
            hit_set, miss_set, fa_set = _match_value(expected_set, detected_filtered)
            hits_typed = list(hit_set)
            misses_typed = list(miss_set)
            fa_typed = list(fa_set)

        result.tp += len(hits_typed)
        result.fn += len(misses_typed)
        result.fp += len(fa_typed)

        for _, etype in hits_typed:
            result.per_type.setdefault(etype, TypeMetrics()).tp += 1
        for _, etype in misses_typed:
            result.per_type.setdefault(etype, TypeMetrics()).fn += 1
        for _, etype in fa_typed:
            result.per_type.setdefault(etype, TypeMetrics()).fp += 1

    result.elapsed_s = time.perf_counter() - t_start
    result.lang = ",".join(sorted(langs_seen)) if langs_seen else "unknown"

    return result


def build_payload(dataset: str, result: Result, engine: dict) -> dict:
    """Build the saved JSON, mirroring the argus per-dataset shape + an engine block.

    ``package_version_string`` is argus's version (the baseline these results are
    compared against); the Presidio version lives in the ``engine`` block.
    """
    per_type = _per_type_dict(result)
    by_class = _by_class_dict(result)
    return {
        "version": ARGUS_VERSION,
        "package_version_string": ARGUS_VERSION,
        "dataset": dataset,
        "language": result.lang,
        "samples": result.n_samples,
        "modes": {
            "presidio": {
                "precision": round(result.precision * 100, 1),
                "recall": round(result.recall * 100, 1),
                "f1": round(result.f1 * 100, 1),
                "per_type": per_type,
                "by_class": by_class,
            }
        },
        "per_type_presidio": per_type,
        "by_class_presidio": by_class,
        "engine": engine,
        "date": datetime.date.today().isoformat(),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="presidio_eval",
        description="Run Microsoft Presidio against the same PII datasets/gold as argus-redact.",
    )
    ap.add_argument("dataset", help="Dataset name (or 'list')")
    ap.add_argument("--lang", default=None, help="Filter by language code")
    ap.add_argument("--limit", type=int, default=1000, help="Max samples")
    ap.add_argument("--match", choices=["value", "span"], default="value", help="Matching strategy")
    ap.add_argument("--save", default=None, metavar="PATH", help="Write result JSON to PATH")
    args = ap.parse_args(argv)

    if args.dataset == "list":
        print("Available datasets:")
        for name in list_adapters():
            print(f"  - {name}")
        return 0

    adapter = get_adapter(args.dataset)
    if args.lang and args.lang not in adapter.languages:
        print(
            f"Warning: {args.dataset} does not list '{args.lang}' "
            f"(available: {', '.join(adapter.languages)}).",
            file=sys.stderr,
        )
        return 1

    analyzer = build_analyzer()
    samples = adapter.load(lang=args.lang, limit=args.limit)
    result = evaluate_presidio(samples, analyzer, match=args.match, dataset_name=args.dataset)
    print_report(result)

    if args.save:
        payload = build_payload(args.dataset, result, engine_block(analyzer))
        save_path = Path(args.save)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"  Saved: {save_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
