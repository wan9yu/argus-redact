"""Unified evaluation engine — run argus-redact against labeled samples."""

from __future__ import annotations

import time
from collections.abc import Iterable

from argus_redact import redact

from .model import Entity, Result, Sample, TypeMetrics


def _match_value(expected: set[tuple[str, str]], detected: set[tuple[str, str]]):
    """Value-level matching: compare (text, type) pairs."""
    hits = expected & detected
    misses = expected - detected
    false_alarms = detected - expected
    return hits, misses, false_alarms


def _match_span(
    expected: list[Entity],
    detected: list[Entity],
    tolerance: int = 3,
):
    """Span-level matching: compare (start, end, type) with positional tolerance.

    Two entities match if their type is equal and both start/end positions
    are within ``tolerance`` characters of each other.
    """
    used = set()
    hits_e: list[Entity] = []
    misses: list[Entity] = []

    for exp in expected:
        matched = False
        for i, det in enumerate(detected):
            if i in used:
                continue
            if (
                det.type == exp.type
                and exp.start is not None
                and det.start is not None
                and abs(det.start - exp.start) <= tolerance
                and abs(det.end - exp.end) <= tolerance
            ):
                used.add(i)
                hits_e.append(exp)
                matched = True
                break
        if not matched:
            misses.append(exp)

    false_alarms = [d for i, d in enumerate(detected) if i not in used]
    return hits_e, misses, false_alarms


def evaluate(
    samples: Iterable[Sample],
    *,
    mode: str = "fast",
    match: str = "value",
    tolerance: int = 3,
    dataset_name: str = "unknown",
) -> Result:
    """Run argus-redact on each sample and compute precision/recall/F1.

    Args:
        samples: Labeled samples to evaluate.
        mode: argus-redact detection mode ("fast", "ner", "auto").
        match: Matching strategy — "value" (text+type) or "span" (position+type).
        tolerance: Character tolerance for span matching.
        dataset_name: Name for the result record.

    Returns:
        Result with overall and per-type metrics.
    """
    result = Result(
        dataset=dataset_name,
        mode=mode,
        lang="",
        n_samples=0,
    )
    langs_seen: set[str] = set()

    t_start = time.perf_counter()

    for sample in samples:
        result.n_samples += 1
        langs_seen.add(sample.lang)

        redacted, key, details = redact(
            sample.text,
            mode=mode,
            lang=sample.lang,
            seed=42,
            detailed=True,
        )

        # Build detected entity set from details
        detected_entities: list[Entity] = []
        for ent in details.get("entities", []):
            detected_entities.append(
                Entity(
                    text=ent["original"],
                    type=ent["type"],
                    start=ent.get("start"),
                    end=ent.get("end"),
                )
            )

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
            # Only evaluate types present in expected
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
