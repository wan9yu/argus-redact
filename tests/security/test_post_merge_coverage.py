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

This file exercises every public entry point the invariant has to hold at:
`redact()`'s internal `_detect` pipeline, the `_pre_detected` path (shared by
`redact()` and `redact_pseudonym_llm()` through `_pre_detected_pipeline` — they
each had their own copy of it, which is how the leak survived in the second one
after the first was fixed), and the structured (`redact_json`/`redact_csv`) and
streaming (`StreamingRedactor`) callers. The data is safe at all of them (the
restore itself is unconditional), but a caller that never sees the
`coverage_restored` signal cannot know a filter tried to drop something it
shouldn't have — so the signal is asserted per entry point, not just once.
"""

import warnings
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from argus_redact import redact
from argus_redact._types import NEREntity, PatternMatch
from argus_redact.exceptions import SecurityWarning
from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm
from argus_redact.layers import LAYER_REGEX, LAYER_SEMANTIC
from argus_redact.pure.replacer import warn_coverage_restored
from argus_redact.streaming import StreamingRedactor
from argus_redact.structured import redact_csv, redact_json

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


@contextmanager
def _stubbed_layers(entity_type, start, end):
    """Both adapter getters patched on the CONSUMING module path.

    Patching only the semantic one would make the result depend on whether NER
    models happen to be installed locally — the documented false-green class in
    this repo.
    """
    with (
        patch("argus_redact.glue.redact._get_ner_adapters", return_value=[_no_ner()]),
        patch(
            "argus_redact.glue.redact._get_semantic_adapter",
            return_value=_semantic(entity_type, start, end),
        ),
    ):
        yield


def _run(entity_type, start, end, *, suppress_warnings=True, **kwargs):
    """Drive `redact()` with L2/L3 stubbed. Pass ``suppress_warnings=False`` to
    observe the SecurityWarning from an enclosing ``pytest.warns`` block."""
    with _stubbed_layers(entity_type, start, end):
        if not suppress_warnings:
            return redact(TEXT, lang="en", mode="auto", salt=42, **kwargs)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            return redact(TEXT, lang="en", mode="auto", salt=42, **kwargs)


def _pre_detected_pair(entity_type: str, start: int, end: int) -> list[PatternMatch]:
    """A (phone, coarse-absorbing-span) pair shaped for the `_pre_detected`
    parameter directly — no mocked adapter needed, since `_pre_detected`
    skips internal detection entirely. `coarse` overlaps and absorbs `phone`
    during merge, the same geometry `_semantic(entity_type, start, end)`
    reproduces via the mocked-adapter path above.
    """
    phone = PatternMatch(
        text=PHONE, type="phone", start=15, end=26, confidence=0.9, layer=LAYER_REGEX
    )
    coarse = PatternMatch(
        text=TEXT[start:end],
        type=entity_type,
        start=start,
        end=end,
        confidence=0.75,
        layer=LAYER_SEMANTIC,
    )
    return [phone, coarse]


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
        with pytest.warns(SecurityWarning, match="lost redaction coverage"):
            redacted, _key = _run("medical", 8, 26, types=["phone"], suppress_warnings=False)
        assert PHONE not in redacted

    def test_an_ordinary_call_does_not_warn_about_coverage(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            redact("张三的手机是13800138000", lang="zh", mode="fast", salt=42)
        assert not [w for w in caught if "lost redaction coverage" in str(w.message)]


class TestPreDetectedBranchOfRedactAlsoHoldsTheInvariant:
    """`redact()`'s `_pre_detected` branch is a SEPARATE code path from
    `_detect()` (merge + type-filter only, never `filter_self_reference`) —
    nothing above drives it. Exercises it end-to-end through the public
    `redact()` boundary so a future edit that flips the `hints=None` choice,
    or drops the `restore_lost_coverage` call from this branch, cannot pass
    silently."""

    def test_types_filter_dropping_a_winner_is_restored_via_pre_detected(self):
        with pytest.warns(SecurityWarning, match="lost redaction coverage"):
            redacted, key = redact(
                TEXT,
                lang="en",
                mode="fast",
                salt=42,
                types=["phone"],
                _pre_detected=_pre_detected_pair("medical", 8, 26),
            )
        assert PHONE not in redacted
        assert key


class TestPseudonymLlmPreDetectedBranchAlsoHoldsTheInvariant:
    """`redact_pseudonym_llm()` has its OWN `_pre_detected` branch (a
    byte-for-byte twin of `redact()`'s, not a call-through to it) — fixing
    `redact()` does not fix this one. `StreamingRedactor` reaches this branch
    on every emit (its `_shift_entities` output is fed in as `_pre_detected`),
    so a leak here is reachable from any streaming caller, not just direct
    callers of `redact_pseudonym_llm`.
    """

    def test_types_filter_dropping_a_winner_is_restored_in_both_text_forms(self):
        with pytest.warns(SecurityWarning, match="lost redaction coverage"):
            result = redact_pseudonym_llm(
                TEXT,
                lang="en",
                mode="fast",
                salt=42,
                types=["phone"],
                _pre_detected=_pre_detected_pair("medical", 8, 26),
            )
        # Both text forms share the one detected-then-filtered entity set —
        # a leak here would appear in BOTH, not just one.
        assert PHONE not in result.downstream_text
        assert PHONE not in result.audit_text
        assert result.key


class TestSignalReachesEveryEntryPoint:
    """`_detect()` restores coverage unconditionally (the data is never at
    risk), but three callers historically discarded the `restored_types`
    out-param instead of threading it to a caller-visible warning:
    `structured.redact_json`/`redact_csv` (per-cell `_detect`) and
    `streaming.StreamingRedactor` (`_context_cut`'s `_detect`, called once per
    round). Each case below is a genuine reproduction (mocked adapters through
    the REAL pipeline, not a mocked `_detect`) — the warning is the only
    channel a caller of these three has for learning a filter tried to drop
    absorbed PII, since none of them expose a `security_events` list.
    """

    def test_redact_json_warns(self):
        with (
            patch("argus_redact.glue.redact._get_ner_adapters", return_value=[_no_ner()]),
            patch(
                "argus_redact.glue.redact._get_semantic_adapter",
                return_value=_semantic("self_reference", 8, 26),
            ),
            pytest.warns(SecurityWarning, match="lost redaction coverage"),
        ):
            data, key = redact_json({"note": TEXT}, mode="auto", lang="en", salt=42)
        assert PHONE not in data["note"]
        assert key

    def test_redact_csv_warns(self):
        csv_text = f"note\n{TEXT}\n"
        with (
            patch("argus_redact.glue.redact._get_ner_adapters", return_value=[_no_ner()]),
            patch(
                "argus_redact.glue.redact._get_semantic_adapter",
                return_value=_semantic("self_reference", 8, 26),
            ),
            pytest.warns(SecurityWarning, match="lost redaction coverage"),
        ):
            redacted_csv, key = redact_csv(csv_text, mode="auto", lang="en", salt=42)
        assert PHONE not in redacted_csv
        assert key

    def test_streaming_redactor_warns_on_flush(self):
        # types=["phone"] is reproduction B's caller-owned filter, driven
        # through StreamingRedactor's constructor exactly as server.py would
        # forward it. feed() alone is under the evidence-context window and
        # provably holds (no _detect call); flush() force-processes the whole
        # buffer, which is where the absorb-then-drop actually happens.
        with (
            patch("argus_redact.glue.redact._get_ner_adapters", return_value=[_no_ner()]),
            patch(
                "argus_redact.glue.redact._get_semantic_adapter",
                return_value=_semantic("medical", 8, 26),
            ),
        ):
            redactor = StreamingRedactor(salt=42, lang="en", mode="auto", types=["phone"])
            redactor.feed(TEXT)
            with pytest.warns(SecurityWarning, match="lost redaction coverage"):
                result = redactor.flush()
        assert PHONE not in result.downstream_text
        assert result.key


class TestTheWarningIsFactualNotAccusatory:
    """The warning fires legitimately on ordinary type-filtered calls (see
    TestTheDefaultTupleCallerIsWarned above) — it must describe the mechanism,
    not accuse the caller of a misconfiguration it cannot tell apart from
    correct, intended use of `types=`/`types_exclude=`."""

    def test_message_names_the_mechanism_not_the_caller(self):
        with pytest.warns(SecurityWarning) as caught:
            warn_coverage_restored(["phone"])
        message = str(caught[0].message)
        assert "absorbed" in message
        assert "merge" in message
        # No longer accuses the caller of an unintended result — the message
        # in place before this fix claimed exactly that, and it is false on
        # the very case (types=/types_exclude=) that fires it in practice.
        assert "did not intend" not in message
        assert "noise" not in message
