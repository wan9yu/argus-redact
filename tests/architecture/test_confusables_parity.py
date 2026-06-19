"""Parity gate: embedded confusables.ron must match the generator output.

Half 1 (always on): the .ron, as text, matches frozen entry count + sha256.
Half 2 (guarded): regenerating from the live generator (which fetches the pinned
Unicode confusables.txt) yields byte-identical .ron. If the generator is later
removed it skips; if the network is unavailable it skips. Half 1 still guards
the embedded data offline.
"""

from __future__ import annotations

import hashlib
import http.client
import urllib.error
from pathlib import Path

import pytest

_RON = (
    Path(__file__).resolve().parents[2]
    / "crates"
    / "argus-redact-core"
    / "data"
    / "confusables.ron"
)


def _ron_text() -> str:
    return _RON.read_text(encoding="utf-8")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── Frozen fingerprints (regenerate intentionally: run make gen-confusables, then
#    update these two constants from the failure output) ──────────────────────
EXPECTED_ENTRY_COUNT = 141
EXPECTED_SHA256 = "38cd34fc6e2b72a85c5c8a7a4cefbff573f3a894a1962aea773a47287b800356"


def test_ron_entry_count_frozen():
    text = _ron_text()
    # one "(...)," row per mapping; structural lines never end in "),"
    count = sum(1 for line in text.splitlines() if line.strip().endswith("),"))
    assert count == EXPECTED_ENTRY_COUNT, f"got {count} mapping rows"


def test_ron_sha256_frozen():
    assert _sha(_ron_text()) == EXPECTED_SHA256


def _regen() -> str | None:
    try:
        from argus_redact.specs.gen_confusables import build_ron, fetch_confusables
    except (ImportError, FileNotFoundError):
        return None
    try:
        text = fetch_confusables()
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        # network unavailable or a flaky/truncated download — skip the live half;
        # the frozen sha256/count half still guards the embedded data offline.
        pytest.skip(f"confusables.txt unavailable (offline/flaky): {e}")
    return build_ron(text)[0]


def test_ron_matches_live_generator():
    regen = _regen()
    if regen is None:
        pytest.skip("specs.gen_confusables removed")
    assert regen == _ron_text(), "confusables.ron drifted; run make gen-confusables"
