"""Schema guard for the committed ai4privacy v0.6.6 benchmark result.

Pinned in v0.6.6 to ensure README's ai4privacy compact table cannot
silently drift from the actual result file.
"""
from __future__ import annotations

import json
from pathlib import Path

_RESULTS = Path(__file__).parent / "results" / "ai4privacy_0.6.6.json"


def test_result_file_present():
    assert _RESULTS.exists(), f"Bench result not committed: {_RESULTS}"


def test_result_file_schema_valid():
    data = json.loads(_RESULTS.read_text(encoding="utf-8"))
    assert data["version"] == "0.6.6"
    assert data["dataset"] == "ai4privacy"
    assert data["samples"] == 500
    assert "modes" in data
    assert set(data["modes"]) >= {"fast", "ner"}, "fast and ner modes are mandatory"
    for mode, vals in data["modes"].items():
        assert set(vals) >= {"precision", "recall", "f1"}, (
            f"mode {mode!r} missing required fields"
        )
        for k, v in vals.items():
            assert isinstance(v, (int, float)), f"mode {mode!r} field {k!r} not numeric"
            assert 0 <= v <= 100, f"mode {mode!r} field {k!r}={v} out of [0,100]"
