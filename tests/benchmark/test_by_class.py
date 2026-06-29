"""Scoped-reporting tests — the structured-vs-free-text PII-class split.

argus is strong on structured identifiers and best-effort on free-text entities;
a single blended recall hides that, so the benchmark reports recall by PII class.
"""

from tests.benchmark.model import FREE_TEXT_TYPES, Result, TypeMetrics, pii_class


def test_pii_class_split():
    assert pii_class("person") == "free_text"
    assert pii_class("location") == "free_text"
    assert pii_class("address") == "free_text"
    assert pii_class("organization") == "free_text"
    assert pii_class("email") == "structured"
    assert pii_class("phone") == "structured"
    assert pii_class("id_number") == "structured"
    assert pii_class("credit_card") == "structured"
    assert FREE_TEXT_TYPES == {"person", "location", "address", "organization"}


def test_by_class_aggregation_and_json():
    r = Result(dataset="d", mode="fast", lang="en", n_samples=1)
    r.per_type = {
        "email": TypeMetrics(tp=99, fp=1, fn=1),        # structured, strong
        "credit_card": TypeMetrics(tp=4, fp=0, fn=44),  # structured, weak recall
        "person": TypeMetrics(tp=10, fp=50, fn=20),     # free_text
        "location": TypeMetrics(tp=82, fp=56, fn=164),  # free_text
    }
    bc = r.by_class()
    assert set(bc) == {"structured", "free_text"}
    # structured = email + credit_card
    assert (bc["structured"].tp, bc["structured"].fp, bc["structured"].fn) == (103, 1, 45)
    # free_text = person + location
    assert (bc["free_text"].tp, bc["free_text"].fp, bc["free_text"].fn) == (92, 106, 184)
    # the whole point: structured recall clearly beats free-text recall
    assert bc["structured"].recall > bc["free_text"].recall
    # surfaced in the saved JSON
    d = r.to_dict()
    assert set(d["by_class"]) == {"structured", "free_text"}
    assert d["by_class"]["structured"]["tp"] == 103
