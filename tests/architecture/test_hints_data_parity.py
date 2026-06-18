"""Data-parity gate for the embedded cross-layer hint tables.

The RON tables in ``crates/argus-redact-core/data/hints.ron`` are the future
single source of truth for the ``text_intent`` / ``self_reference_tier`` hint
logic. They are the aggregated copy of the per-language ``lang/<code>/hints.py``
sources (combined by ``pure/hints.py``'s ``_collect``), and a single dropped or
changed entry would silently break that logic. This gate locks that copy.

Two halves, by design:

1. **Frozen-fingerprint half (always runs).** Hard-coded ``EXPECTED_COUNTS`` and
   ``EXPECTED_SHA256`` were captured from the live aggregated Python tables at
   port time. The test ALWAYS asserts the ``_core`` RON-loaded pools match those
   frozen counts + sha256. This half has NO dependency on the Python tables, so
   it survives any later deletion of ``pure/hints.py`` / the ``lang/*/hints.py``
   sources.

2. **Live-source half (runs only while the Python tables exist).** Wrapped in
   ``try/except (ImportError, FileNotFoundError)``: when the tables are present
   it imports ``argus_redact.pure.hints`` and asserts the ``_core`` RON pools
   equal the aggregated ``_KINSHIP_EXACT`` / ``_KINSHIP_PREFIXES`` /
   ``_COMMAND_PREFIXES`` / ``_COMMAND_SUFFIXES`` as SETS, and the command-pattern
   ``(source, ignorecase)`` pairs as a SET — matching the SAME frozen
   fingerprints. When the tables are gone, this half is skipped.

Net effect: today this proves ``RON == aggregated Python == frozen-truth``;
forever after it proves ``RON == frozen-truth``.

The fingerprints are stable because each list pool is hashed over the canonical
``"\\n".join(sorted(pool))`` (order-independent); the command patterns are hashed
over a canonical sorted join of ``pattern + "\\x00" + ("i" if ignorecase else "")``.
"""

from __future__ import annotations

import hashlib

import pytest

import argus_redact._core as _core

# ── Frozen fingerprints (captured from the live aggregated tables at port time) ──

EXPECTED_COUNTS = {
    "kinship_exact": 66,
    "kinship_prefixes": 16,
    "command_prefixes": 14,
    "command_suffixes": 12,
    "command_patterns": 5,
}

EXPECTED_SHA256 = {
    # sha256 over "\n".join(sorted(pool)) (order-independent).
    "kinship_exact": "52b4c0a5723f9be4a7e77226954a492e6b99bd300c624a48a0936c8db4d3abd3",
    "kinship_prefixes": "410334e8545692b76ecc644f84d6205e2bf939fe4503ea888b56df0c380ffc4e",
    "command_prefixes": "8f4483fc2c86f9f72770c9bbf19f242fbebf0c88396674c6a81abdfd2351cc34",
    "command_suffixes": "05f07949cd776ca734ae6c8648f3cb087b9e7e1df697a07ed83eaf4864b416ab",
    # sha256 over "\n".join(sorted(pattern + "\x00" + ("i" if ignorecase else ""))).
    "command_patterns": "76a5ea44f0c0702054e1adcccb5e8dabbb0b5061357bbf95143e6121860b7bfe",
}

_LIST_POOLS = (
    "kinship_exact",
    "kinship_prefixes",
    "command_prefixes",
    "command_suffixes",
)


def _sha_list(pool) -> str:
    """Canonical, order-independent fingerprint of a string-list pool."""
    return hashlib.sha256("\n".join(sorted(pool)).encode("utf-8")).hexdigest()


def _canon_patterns(pairs) -> list[str]:
    """Canonical, order-independent representation of (source, ignorecase) pairs."""
    return sorted(src + "\x00" + ("i" if ic else "") for src, ic in pairs)


def _sha_patterns(pairs) -> str:
    return hashlib.sha256("\n".join(_canon_patterns(pairs)).encode("utf-8")).hexdigest()


def _core_pools() -> dict[str, object]:
    """RON-loaded pools via the ``_core`` accessors (the side under test)."""
    return {
        "kinship_exact": list(_core.hint_kinship_exact()),
        "kinship_prefixes": list(_core.hint_kinship_prefixes()),
        "command_prefixes": list(_core.hint_command_prefixes()),
        "command_suffixes": list(_core.hint_command_suffixes()),
        # list[(str, bool)]
        "command_patterns": [tuple(p) for p in _core.hint_command_patterns()],
    }


# ── Half 1: frozen-fingerprint side (always runs; survives table deletion) ────


def test_core_pools_match_frozen_counts():
    pools = _core_pools()
    for key in _LIST_POOLS:
        assert len(pools[key]) == EXPECTED_COUNTS[key], key
        # RON list pools carry no duplicates.
        assert len(set(pools[key])) == EXPECTED_COUNTS[key], f"{key} has duplicates"
    assert len(pools["command_patterns"]) == EXPECTED_COUNTS["command_patterns"]
    assert (
        len(set(pools["command_patterns"])) == EXPECTED_COUNTS["command_patterns"]
    ), "command_patterns has duplicates"


def test_core_pools_match_frozen_sha256():
    pools = _core_pools()
    for key in _LIST_POOLS:
        assert _sha_list(pools[key]) == EXPECTED_SHA256[key], key
    assert _sha_patterns(pools["command_patterns"]) == EXPECTED_SHA256["command_patterns"]


# ── Half 2: live aggregated Python-table side (skipped if hints.py is gone) ───


def _load_python_truth() -> dict[str, object] | None:
    """Derive the truth from the live aggregated ``pure.hints`` attributes.

    Returns ``None`` (and the caller skips) if ``pure.hints`` (or any
    ``lang/<code>/hints.py`` it aggregates) has been removed.
    """
    import re

    try:
        import argus_redact.pure.hints as h

        return {
            "kinship_exact": set(h._KINSHIP_EXACT),
            "kinship_prefixes": set(h._KINSHIP_PREFIXES),
            "command_prefixes": set(h._COMMAND_PREFIXES),
            "command_suffixes": set(h._COMMAND_SUFFIXES),
            "command_patterns": {
                (p.pattern, bool(p.flags & re.IGNORECASE)) for p in h._COMMAND_PATTERNS
            },
        }
    except (ImportError, FileNotFoundError):
        return None


def test_python_source_matches_frozen_fingerprints():
    truth = _load_python_truth()
    if truth is None:
        pytest.skip("Aggregated Python hint tables removed (pure.hints gone)")
    # Counts (sets — the aggregated pools may contain cross-language duplicates,
    # e.g. en/uk/in_ all contribute "my "; membership is what the RON locks).
    for key in _LIST_POOLS:
        assert len(truth[key]) == EXPECTED_COUNTS[key], key
    assert len(truth["command_patterns"]) == EXPECTED_COUNTS["command_patterns"]
    # sha256.
    for key in _LIST_POOLS:
        assert _sha_list(truth[key]) == EXPECTED_SHA256[key], key
    assert _sha_patterns(truth["command_patterns"]) == EXPECTED_SHA256["command_patterns"]


def test_core_pools_equal_python_source():
    truth = _load_python_truth()
    if truth is None:
        pytest.skip("Aggregated Python hint tables removed (pure.hints gone)")
    pools = _core_pools()
    # All string pools: full membership comparison as sets (order-independent).
    for key in _LIST_POOLS:
        assert set(pools[key]) == truth[key], key
    # Command patterns: (source, ignorecase) pairs compared as a set.
    assert set(pools["command_patterns"]) == truth["command_patterns"]


if __name__ == "__main__":
    # Convenience: print the live fingerprints so they can be re-frozen on a
    # deliberate source change (review the diff before updating).
    truth = _load_python_truth()
    if truth is None:
        raise SystemExit("Python hint tables unavailable; cannot recompute fingerprints.")
    print("EXPECTED_COUNTS = {")
    for key in _LIST_POOLS:
        print(f'    "{key}": {len(truth[key])},')
    print(f'    "command_patterns": {len(truth["command_patterns"])},')
    print("}")
    print("EXPECTED_SHA256 = {")
    for key in _LIST_POOLS:
        print(f'    "{key}": "{_sha_list(truth[key])}",')
    print(f'    "command_patterns": "{_sha_patterns(truth["command_patterns"])}",')
    print("}")
