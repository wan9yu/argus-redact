"""Layer-3 failure logging must not leak input fragments.

When ``mode="auto"`` Layer-3 (semantic LLM) detection raises, the redact glue
catches it and continues with L1+L2. The log line for that failure must record
only the exception TYPE — never a full traceback (``exc_info=True``), which can
embed input text passed through the adapter call frames.
"""

from __future__ import annotations

import logging

from argus_redact import redact

# Marker chosen to look like a secret in the user's input. If a traceback is
# logged, this string can surface in the exception's args/frames.
_SECRET = "SSN 123-45-6789 belongs to John Smith"


def _force_l3_failure(monkeypatch):
    """Wire mode='auto' so L2 is unavailable (warn, not raise) and L3 raises."""
    import argus_redact.glue.redact as r

    monkeypatch.setattr(r, "_get_ner_adapters", lambda lang: [])
    monkeypatch.setattr(r, "_get_semantic_adapter", lambda: object())

    def _boom(text, adapter):  # noqa: ARG001 - signature match
        raise RuntimeError(f"adapter exploded while processing: {text}")

    import argus_redact.impure.semantic as sem

    monkeypatch.setattr(sem, "detect_semantic", _boom)


def test_l3_failure_logs_exception_type_not_traceback(monkeypatch, caplog):
    _force_l3_failure(monkeypatch)

    with caplog.at_level(logging.WARNING, logger="argus_redact"):
        # SecurityWarning for the no-NER-model degradation is expected; filter
        # away so it doesn't turn into an error under -W settings.
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            redact(_SECRET, lang="en", mode="auto", salt=b"\x00" * 32)

    l3_records = [rec for rec in caplog.records if "Layer 3" in rec.getMessage()]
    assert l3_records, "expected a Layer-3 failure log record"
    rec = l3_records[0]

    # The exception TYPE name must be present.
    assert "RuntimeError" in rec.getMessage()

    # No traceback attached (exc_info=True sets rec.exc_info to the exc tuple).
    assert rec.exc_info is None, "Layer-3 log must not carry a traceback"

    # The raw input fragment must not appear anywhere in the rendered record.
    rendered = rec.getMessage()
    assert "123-45-6789" not in rendered
    assert "John Smith" not in rendered
