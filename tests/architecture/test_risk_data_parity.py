"""Parity gate: embedded risk_data.ron must match the Python registry SSOT.

Half 1 (always on): the .ron, parsed, matches frozen counts + sha256 fingerprints.
Half 2 (guarded): regenerating from the live registry yields byte-identical .ron.
If specs.gen_risk_data / the registry is later removed, Half 2 skips; Half 1 still
guards the embedded data.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

_RON = (
    Path(__file__).resolve().parents[2] / "crates" / "argus-redact-core" / "data" / "risk_data.ron"
)


def _ron_text() -> str:
    return _RON.read_text(encoding="utf-8")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── Frozen fingerprints (regenerate intentionally: run make gen-risk-data, then
#    update these two constants from the failure output) ──────────────────────
EXPECTED_TYPE_COUNT = 74
EXPECTED_SHA256 = "9f5b8ed884fb4a2ae4a3383c1b779a37c44f9a7a8ed93ed5e246bbda49c6a700"


def test_ron_type_count_frozen():
    text = _ron_text()
    # one "(lang:" opener per type row
    count = text.count("(lang: ")
    assert count == EXPECTED_TYPE_COUNT, f"got {count} type rows"


def test_ron_sha256_frozen():
    assert _sha(_ron_text()) == EXPECTED_SHA256


def _regen() -> str | None:
    try:
        from argus_redact.specs.gen_risk_data import build_ron

        return build_ron()
    except (ImportError, FileNotFoundError):
        return None


def test_ron_matches_live_registry():
    regen = _regen()
    if regen is None:
        pytest.skip("specs.gen_risk_data removed")
    assert regen == _ron_text(), "risk_data.ron drifted from registry; run make gen-risk-data"
