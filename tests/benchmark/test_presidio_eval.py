"""Presidio head-to-head benchmark tests.

Skips cleanly when the optional ``presidio`` extra is not installed (CI may omit
it). Asserts the eval (a) produces the argus-comparable schema (incl. the
structured-vs-free-text ``by_class`` split), (b) is non-vacuous — Presidio
actually detects the email, proving it ran — and (c) honors the SAME fairness
rule as the argus evaluator: a detection of a type the dataset does not label is
ignored, never counted as a false positive.
"""

from __future__ import annotations

import pytest

from tests.benchmark.model import Entity, Sample

_ANALYZER = None


def _get_analyzer():
    """Build the AnalyzerEngine once and cache it (loading the model is slow)."""
    global _ANALYZER
    if _ANALYZER is None:
        from tests.benchmark.presidio_eval import build_analyzer

        _ANALYZER = build_analyzer()
    return _ANALYZER


def _inline_samples() -> list[Sample]:
    return [
        Sample(
            text="Email me at john.doe@example.com about the renewal.",
            lang="en",
            entities=[Entity(text="john.doe@example.com", type="email")],
        ),
        Sample(
            text="Please call John Smith at 212-555-0143 tomorrow.",
            lang="en",
            entities=[
                Entity(text="John Smith", type="person"),
                Entity(text="212-555-0143", type="phone"),
            ],
        ),
    ]


def test_schema_and_nonvacuous():
    pytest.importorskip("presidio_analyzer")
    from tests.benchmark.presidio_eval import evaluate_presidio

    result = evaluate_presidio(
        _inline_samples(), _get_analyzer(), match="value", dataset_name="inline"
    )
    d = result.to_dict()
    # (a) argus-comparable schema, incl. the by_class split
    assert {"precision", "recall", "f1", "per_type", "by_class"} <= set(d)
    assert set(d["by_class"]) <= {"structured", "free_text"}
    # (b) non-vacuous: Presidio actually detected the email (proves it ran)
    assert "email" in result.per_type
    assert result.per_type["email"].tp >= 1


def test_fairness_unlabeled_type_is_not_a_false_positive():
    pytest.importorskip("presidio_analyzer")
    from tests.benchmark.presidio_eval import evaluate_presidio

    # Gold labels ONLY the email; the text also contains a person name that
    # Presidio will detect — under the fairness rule that detection is ignored,
    # exactly as the argus evaluator ignores types absent from the gold.
    sample = Sample(
        text="Contact John Smith at john.doe@example.com please.",
        lang="en",
        entities=[Entity(text="john.doe@example.com", type="email")],
    )
    result = evaluate_presidio([sample], _get_analyzer(), match="value", dataset_name="fair")
    assert "person" not in result.per_type  # unlabeled type is never scored
    assert result.fp == 0  # so no spurious false positive is created
    assert result.per_type["email"].tp == 1
