"""Invariant: redact_pseudonym_llm() runs detection exactly once per call.

The pseudonym-llm profile produces three text forms (audit/downstream/display)
from a SINGLE entity set. Detection must run once and replacement must run twice
(once for the realistic config, once for the audit config). Doubling detection
would double NER/LLM cost in mode="ner"/"auto".
"""

from __future__ import annotations

from argus_redact.glue import redact as redact_module
from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm


class TestDetectionInvariant:
    def test_should_run_detect_once_and_replace_twice(self, monkeypatch):
        text = "请拨打 13912345678"

        detect_calls = 0
        replace_calls = 0

        real_detect = redact_module._detect
        real_replace_and_emit = redact_module._replace_and_emit

        def counting_detect(*args, **kwargs):
            nonlocal detect_calls
            detect_calls += 1
            return real_detect(*args, **kwargs)

        def counting_replace_and_emit(*args, **kwargs):
            nonlocal replace_calls
            replace_calls += 1
            return real_replace_and_emit(*args, **kwargs)

        monkeypatch.setattr(redact_module, "_detect", counting_detect)
        monkeypatch.setattr(redact_module, "_replace_and_emit", counting_replace_and_emit)

        redact_pseudonym_llm(text)

        assert detect_calls == 1, f"_detect should run exactly once, ran {detect_calls}"
        assert replace_calls == 2, f"_replace_and_emit should run exactly twice, ran {replace_calls}"
