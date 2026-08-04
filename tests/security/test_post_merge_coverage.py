"""A post-merge filter must never un-redact PII the merge already absorbed.

Two reproductions, both driven through the PUBLIC redact() boundary so the
assertions are about what the CALLER receives, not about internal state:

  A. A poisoned or prompt-injected L3 model returns type='self_reference' over a
     span containing a real phone. The priority merge lets it win, then the
     self-reference tier filter drops the winner.
  B. A benign but coarse L3 model tags a longer span with a legitimate registry
     type. The caller's own types=["phone"] filter then drops the winner.

Variant B needs no hostile model at all, and both `mode` and `types` are
forwarded from HTTP request bodies by src/argus_redact/server.py.
"""

import warnings
from unittest.mock import MagicMock, patch

import pytest

from argus_redact import redact
from argus_redact._types import NEREntity
from argus_redact.exceptions import SecurityWarning

TEXT = "Contact number 13800138000 for details"
PHONE = "13800138000"


def _semantic(entity_type: str, start: int, end: int):
    """An L3 adapter that returns one span of `entity_type` covering the phone."""
    adapter = MagicMock()
    adapter.detect.return_value = [NEREntity(TEXT[start:end], entity_type, start, end, 0.75)]
    return adapter


def _no_ner():
    ner = MagicMock()
    ner.detect.return_value = []
    return ner


def _run(entity_type, start, end, **kwargs):
    with (
        patch("argus_redact.glue.redact._get_ner_adapters", return_value=[_no_ner()]),
        patch(
            "argus_redact.glue.redact._get_semantic_adapter",
            return_value=_semantic(entity_type, start, end),
        ),
        warnings.catch_warnings(),
    ):
        warnings.simplefilter("ignore", SecurityWarning)
        return redact(TEXT, lang="en", mode="auto", salt=42, **kwargs)


class TestSelfReferenceTypeConfusion:
    def test_whole_document_span_does_not_leak(self):
        redacted, key = _run("self_reference", 0, len(TEXT))
        assert PHONE not in redacted
        assert key

    def test_span_starting_before_the_victim_does_not_leak(self):
        redacted, key = _run("self_reference", 8, 26)
        assert PHONE not in redacted
        assert key

    def test_exact_same_span_does_not_leak(self):
        redacted, key = _run("self_reference", 15, 26)
        assert PHONE not in redacted
        assert key


class TestTypeFilterDropsAWinner:
    def test_requested_type_is_not_returned_in_plaintext(self):
        redacted, key = _run("medical", 8, 26, types=["phone"])
        assert PHONE not in redacted
        assert key

    def test_excluding_the_winner_does_not_expose_the_loser(self):
        redacted, key = _run("medical", 8, 26, types_exclude=["medical"])
        assert PHONE not in redacted
        assert key

    def test_benign_case_without_a_filter_is_unchanged(self):
        redacted, _key = _run("medical", 8, 26)
        assert PHONE not in redacted


class TestTheComplianceArtifactsTellTheTruth:
    def test_report_does_not_claim_clean_while_restoring(self):
        report = _run("medical", 8, 26, types=["phone"], report=True)
        assert PHONE not in report.redacted_text
        assert report.residual_personal_data is True
        assert report.risk.level != "none"

    def test_report_carries_the_coverage_restored_event(self):
        report = _run("medical", 8, 26, types=["phone"], report=True)
        events = [e for e in report.security_events if e["reason_code"] == "coverage_restored"]
        assert len(events) == 1
        assert events[0]["type"] == "security"
        assert events[0]["count"] == 1
        assert events[0]["detail"] == "types: phone"
        # PII-free: the value never appears in the event.
        assert PHONE not in events[0]["detail"]


class TestTheDefaultTupleCallerIsWarned:
    def test_a_firing_warns_even_on_the_two_tuple_path(self):
        with (
            patch("argus_redact.glue.redact._get_ner_adapters", return_value=[_no_ner()]),
            patch(
                "argus_redact.glue.redact._get_semantic_adapter",
                return_value=_semantic("medical", 8, 26),
            ),
            pytest.warns(SecurityWarning, match="lost redaction coverage"),
        ):
            redacted, _key = redact(TEXT, lang="en", mode="auto", salt=42, types=["phone"])
        assert PHONE not in redacted

    def test_an_ordinary_call_does_not_warn_about_coverage(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            redact("张三的手机是13800138000", lang="zh", mode="fast", salt=42)
        assert not [w for w in caught if "lost redaction coverage" in str(w.message)]
