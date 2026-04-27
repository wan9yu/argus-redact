"""Realistic scenario tests — synthetic but real-world-like PII patterns."""

import json
from pathlib import Path

import pytest

from argus_redact import redact, restore

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _load():
    with open(FIXTURES_DIR / "realistic_scenarios.json", encoding="utf-8") as f:
        return json.load(f)


_cases = _load()


@pytest.mark.parametrize("case", _cases, ids=[c["id"] for c in _cases])
class TestRealisticScenarios:
    def test_should_not_crash(self, case):
        lang = case.get("lang", "zh")

        redacted, key = redact(case["input"], seed=42, mode="fast", lang=lang)

        assert isinstance(redacted, str)
        assert isinstance(key, dict)

    def test_should_detect_pii(self, case):
        if not case.get("pii_values"):
            pytest.skip("no PII expected")

        lang = case.get("lang", "zh")

        redacted, key = redact(case["input"], seed=42, mode="fast", lang=lang)

        for pii in case["pii_values"]:
            assert pii not in redacted, f"PII '{pii}' not redacted: {case['description']}"

    def test_should_roundtrip(self, case):
        if not case.get("pii_values"):
            pytest.skip("no PII expected")

        lang = case.get("lang", "zh")

        redacted, key = redact(case["input"], seed=42, mode="fast", lang=lang)
        restored = restore(redacted, key)

        for pii in case["pii_values"]:
            assert pii in restored, f"PII '{pii}' not recovered: {case['description']}"
