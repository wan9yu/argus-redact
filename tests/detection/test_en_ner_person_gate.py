"""L2 English NER `person` candidates are evidence-gated through the L1 scorer.

spaCy English NER (`en_core_web_sm`) is high-recall/noisy on prose; ungated, its
`person` spans enter the result set raw and wreck precision (a benchmark showed
kaggle_piilo person precision collapse under `mode="ner"`). The glue now routes
each English L2 `person` candidate through the SAME Rust evidence scorer L1 uses
(`person_en::score_person_candidate`, single-sourced), keeping title / name-like /
PII-proximate spans and dropping uncorroborated bare-prose ones.

CRITICAL — the local suite is a FALSE GREEN for NER-gating: it has the real NER
models installed AND deselects `-m ner`, so a test that relied on the real spaCy
model would either be skipped or non-deterministic. These tests therefore MOCK
`_get_ner_adapters` to inject a stub adapter returning controlled spaCy-style
`person` candidates, so they run deterministically WITHOUT the real model and
WITHOUT the `ner` marker. The real cross-platform proof is Tests-on-main CI.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from argus_redact import redact, restore
from argus_redact._types import NEREntity
from argus_redact.impure.ner import NERAdapter


def _stub_adapter(candidates: list[NEREntity], *, lang: str | None):
    """A stub NER adapter that returns `candidates` regardless of input text.

    `lang` mirrors the real adapter's language marker the L2 glue reads to decide
    whether to apply the English `person` gate.
    """
    adapter = MagicMock(spec=NERAdapter)
    adapter.lang = lang
    adapter.detect.return_value = candidates
    return adapter


def _ent(text: str, sub: str, etype: str = "person", conf: float = 0.85) -> NEREntity:
    start = text.index(sub)
    return NEREntity(sub, etype, start, start + len(sub), conf)


# ── English `person` gating ─────────────────────────────────────────────────


def test_en_ner_drops_uncorroborated_bare_prose_person():
    """A spaCy `person` whose lead is a common/place word ("Central Park"), with no
    title and no nearby PII, is DROPPED by the gate — so it survives in the output
    unredacted (L1 also misses it, so the L2 candidate was its only redaction path).
    """
    text = "Central Park hosted the spring fair this year."
    stub = _stub_adapter([_ent(text, "Central Park")], lang="en")
    with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[stub]):
        redacted, key = redact(text, salt=42, mode="ner", lang="en")
    # Gate dropped the candidate → the span is untouched.
    assert "Central Park" in redacted
    assert "Central Park" not in key.values()


def test_en_ner_keeps_name_like_person_l1_misses():
    """A spaCy single-token `person` L1 cannot reach ("Obama" — no surname anchor)
    survives the gate via the name-like signal and IS redacted. Proves the gate is
    not a blanket drop and that L2 still adds recall over L1.
    """
    text = "Obama gave a speech downtown."
    stub = _stub_adapter([_ent(text, "Obama")], lang="en")
    with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[stub]):
        redacted, key = redact(text, salt=42, mode="ner", lang="en")
    assert "Obama" not in redacted
    assert "Obama" in key.values()
    assert restore(redacted, key) == text


def test_en_ner_gate_is_selective_drop_and_keep_together():
    """Both candidates injected at once: the common-word FP is dropped, the
    name-like name is kept — single pass, selective filtering (non-vacuous).
    """
    text = "Central Park is where Obama once walked."
    stub = _stub_adapter([_ent(text, "Central Park"), _ent(text, "Obama")], lang="en")
    with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[stub]):
        redacted, key = redact(text, salt=42, mode="ner", lang="en")
    assert "Central Park" in redacted  # FP dropped
    assert "Obama" not in redacted  # real name kept + redacted


def test_en_ner_keeps_pii_proximate_person():
    """A bare common-word lead ("Lake Park") near structural PII (a phone) clears
    the gate via the proximity signal and is redacted — exercising the L1 pii
    proximity signal wired through the L2 gate.
    """
    text = "Reach Lake Park at 415-555-1234 anytime."
    stub = _stub_adapter([_ent(text, "Lake Park")], lang="en")
    with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[stub]):
        redacted, key = redact(text, salt=42, mode="ner", lang="en")
    assert "Lake Park" not in redacted
    assert "Lake Park" in key.values()


def test_en_ner_non_person_types_unaffected():
    """The gate touches ONLY `person`; location/organization spaCy candidates pass
    through unchanged even when their text would fail the person gate.
    """
    text = "Central Park is in New York."
    stub = _stub_adapter([_ent(text, "Central Park", etype="location")], lang="en")
    with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[stub]):
        redacted, key = redact(text, salt=42, mode="ner", lang="en")
    # Kept as a location (the person gate never saw it).
    assert "Central Park" not in redacted
    assert "Central Park" in key.values()


# ── zh untouched (the gate is English-only) ─────────────────────────────────


def test_zh_ner_person_untouched_by_en_gate():
    """A non-English adapter (lang != "en") bypasses the English gate entirely, so
    a zh `person` candidate is redacted exactly as before — even one whose first
    char would never pass the English name-like test.
    """
    text = "张三去了北京。"
    stub = _stub_adapter([NEREntity("张三", "person", 0, 2, 0.95)], lang="zh")
    with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[stub]):
        redacted, key = redact(text, salt=42, mode="ner", lang="zh")
    assert "张三" not in redacted
    assert "张三" in key.values()
