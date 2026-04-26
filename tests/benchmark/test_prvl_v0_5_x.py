"""PRvL baseline for argus-redact v0.5.x — pseudonym-llm profile vs default placeholder.

Quantifies LLM Reversibility (R), Usability (U), Language preservation (L) for:
- ``zh_fast``: zh fast-mode redact via default profile vs pseudonym-llm
- ``en_fast``: en fast-mode redact (v0.5.3 surname-list person detection)
- ``mixed_auto``: zh+en mixed via ``lang="auto"``
- ``streaming``: 3 chunks via StreamingRedactor with cross-chunk consistency

Each scenario × 3 LLMs (GPT-4o / Claude / Gemini) = 12 baseline data points.

LLM-driven tests are gated on the POE_API_KEY environment variable (sync with
``test_prvl_multi_llm.py``). Run locally:
    POE_API_KEY=... pytest tests/benchmark/test_prvl_v0_5_x.py -v -s -m semantic

Then commit the resulting numbers to
``tests/benchmark/fixtures/prvl_v0_5_x_baseline.json`` and append a section
to ``docs/benchmark-report.md``.

The committed JSON shape (see fixture file's leading comment line):
    {
      "<scenario>|<llm>": {
        "R_default": float,        # default placeholder profile reversibility
        "R_realistic": float,      # pseudonym-llm profile reversibility
        "U_realistic": float,      # downstream LLM usability score 0-1
        "L_match": "<lang>",       # language of LLM output (matches input?)
        "tested_at": "<iso-8601>"
      },
      ...
    }
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# LLM-gated marker matching test_prvl_multi_llm.py convention.
_LLM_GATE = pytest.mark.skipif(
    not os.environ.get("POE_API_KEY"),
    reason="LLM-driven baseline; requires POE_API_KEY (see module docstring)",
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "prvl_v0_5_x_baseline.json"

LLMS = ("GPT-4o", "Claude-3.7-Sonnet", "Gemini-2.0-Flash")

SCENARIOS = {
    "zh_fast": {
        "lang": "zh",
        "mode": "fast",
        "text": "客户王建国电话13912345678，身份证110101199003077651，确诊高血压",
        "prompt": "请用一句话总结：{text}",
        "task_type": "reference",
    },
    "en_fast": {
        "lang": "en",
        "mode": "fast",
        "text": "Call John Smith at (415) 555-1234, SSN 123-45-6789. Diagnosed with hypertension.",
        "prompt": "Summarize in one sentence: {text}",
        "task_type": "reference",
    },
    "mixed_auto": {
        "lang": "auto",
        "mode": "fast",
        "text": "客户Wang at user@company.com phoned 13912345678 about diabetes care.",
        "prompt": "Translate to English and summarize: {text}",
        "task_type": "reference",
    },
    # streaming scenario uses StreamingRedactor; "text" is the joined chunks
    "streaming": {
        "lang": "zh",
        "mode": "fast",
        "text": "请联系王建国。他的手机号是13912345678。地址北京朝阳。",
        "chunks": [
            "请联系王建国。",
            "他的手机号是13912345678。",
            "地址北京朝阳。",
        ],
        "prompt": "请总结：{text}",
        "task_type": "reference",
    },
}


class TestPRvLv0_5xBaselineFixtureContract:
    """Always runs (no LLM). Verifies the committed baseline file contract."""

    def test_fixture_shape_when_present(self):
        if not FIXTURE_PATH.exists():
            pytest.skip("baseline fixture not committed yet; run with POE_API_KEY first")
        try:
            data = json.loads(FIXTURE_PATH.read_text())
        except json.JSONDecodeError as e:
            pytest.fail(f"baseline fixture is not valid JSON: {e}")
        if not data:
            pytest.skip("baseline fixture is empty (placeholder); run with POE_API_KEY")
        for scenario in SCENARIOS:
            for llm in LLMS:
                key = f"{scenario}|{llm}"
                assert key in data, f"missing baseline entry: {key}"
                fields = set(data[key].keys())
                expected = {"R_default", "R_realistic", "U_realistic", "L_match", "tested_at"}
                assert expected <= fields, f"{key} missing fields: {expected - fields}"


@_LLM_GATE
@pytest.mark.semantic
class TestPRvLv0_5xBaselineRun:
    """Actual LLM round-trips. Skipped without POE_API_KEY.

    The runner body is intentionally a manual procedure — see module docstring.
    Parametrization is omitted to keep the collection clean; the maintainer
    iterates SCENARIOS × LLMS by hand when running with API access.
    """

    def test_run_baseline_manually(self):
        # Implementation: for each (scenario, llm), call default redact +
        # pseudonym-llm; send each downstream to the LLM via Poe API; restore
        # both; compute R/U/L. Maintainer captures numbers into the fixture
        # JSON + benchmark-report.md.
        pytest.skip(
            "Manual baseline run — call LLM, capture R/U/L, write to fixture. "
            "See module docstring for the procedure."
        )
