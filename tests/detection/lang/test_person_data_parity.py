"""Data-parity gate for the embedded zh + en person-name pools.

The RON pools in ``crates/argus-redact-core/data/{zh,en}_person.ron`` are the
future single source of truth for fast-mode (no-NER) person detection. They are
a byte-faithful copy of the current pure-Python sources, and a single dropped or
changed entry would silently break detection later. This gate locks that copy.

Two halves, by design:

1. **Frozen-fingerprint half (always runs).** Hard-coded ``EXPECTED_COUNTS`` and
   ``EXPECTED_SHA256`` were captured from the live Python sources at port time.
   The test ALWAYS asserts the ``_core`` RON-loaded pools match those frozen
   counts + sha256. This half has NO dependency on the Python sources, so it
   survives Task 9 (which deletes ``lang/zh/surnames.py``, ``not_names.txt``,
   ``common_words.txt``, ``lang/en/given_names.py``, ``lang/en/surnames.py``).

2. **Live-source half (runs only while the Python sources exist).** Wrapped in
   ``try/except (ImportError, FileNotFoundError)``: when the sources are present
   (today, pre-T9) it derives the truth from the ACTUAL Python objects/loaders
   and asserts they match the SAME frozen counts + sha256 AND equal the ``_core``
   pools as sets (full membership) + SURNAMES as an exact string. When the
   sources are gone (post-T9), this half is skipped.

Net effect: today this proves ``RON == Python source == frozen-truth``; forever
after it proves ``RON == frozen-truth``.

The fingerprints are stable because each list pool is hashed over the canonical
``"\\n".join(sorted(pool))`` (order-independent) and the surnames string is
hashed raw (order-load-bearing, exact string).
"""

from __future__ import annotations

import hashlib

import pytest

import argus_redact._core as _core

# ── Frozen fingerprints (captured from the live Python sources at port time) ──

EXPECTED_COUNTS = {
    "surnames_zh": 138,        # distinct chars in SURNAMES string
    "compound_surnames_zh": 16,
    "not_names_zh": 7533,
    "common_words_zh": 31257,
    "given_names_en": 199,
    "surnames_en": 615,
}

EXPECTED_SHA256 = {
    # sha256 over the raw SURNAMES string (order-load-bearing, exact).
    "surnames_zh": "8db618e15616cacb112c44167b80cef15f62e2558065e27f601dc39b2f1cebcc",
    # sha256 over "\n".join(sorted(pool)) (order-independent).
    "compound_surnames_zh": "e4c54f36dfabff6b2ba5e995a9382d7b4eaa5457a52e4917b58002e9e41b2af8",
    "not_names_zh": "f329de7ddba52e49c3ab740b9e63150d10a1134399e0bf06f041e4d7f35c18c5",
    "common_words_zh": "a725bd410a74cd222151d9dd719472b5e2649873483862a2a15a949ef55543fe",
    "given_names_en": "fa796ed470e997631ee1956f41c1d161cd9a5673e25f7feeccef97665db6bf77",
    "surnames_en": "1fefac4e9cad7cbfa561ccce81232f952a8ab781404ced944cab506e5e86626b",
}


def _sha_list(pool) -> str:
    """Canonical, order-independent fingerprint of a list pool."""
    return hashlib.sha256("\n".join(sorted(pool)).encode("utf-8")).hexdigest()


def _sha_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _core_pools() -> dict[str, object]:
    """RON-loaded pools via the ``_core`` accessors (the side under test)."""
    return {
        "surnames_zh": _core.person_surnames_zh(),  # str
        "compound_surnames_zh": list(_core.person_compound_surnames_zh()),
        "not_names_zh": list(_core.person_not_names_zh()),
        "common_words_zh": list(_core.person_common_words_zh()),
        "given_names_en": list(_core.person_given_names_en()),
        "surnames_en": list(_core.person_surnames_en()),
    }


_LIST_POOLS = (
    "compound_surnames_zh",
    "not_names_zh",
    "common_words_zh",
    "given_names_en",
    "surnames_en",
)


# ── Half 1: frozen-fingerprint side (always runs; survives T9) ────────────────


def test_core_pools_match_frozen_counts():
    pools = _core_pools()
    # surnames is a char string; its "count" is the number of distinct chars.
    assert len(set(pools["surnames_zh"])) == EXPECTED_COUNTS["surnames_zh"]
    for key in _LIST_POOLS:
        assert len(pools[key]) == EXPECTED_COUNTS[key], key
        # RON list pools carry no duplicates.
        assert len(set(pools[key])) == EXPECTED_COUNTS[key], f"{key} has duplicates"


def test_core_pools_match_frozen_sha256():
    pools = _core_pools()
    # surnames: exact-string fingerprint (order-load-bearing).
    assert _sha_str(pools["surnames_zh"]) == EXPECTED_SHA256["surnames_zh"]
    # list pools: order-independent set fingerprint.
    for key in _LIST_POOLS:
        assert _sha_list(pools[key]) == EXPECTED_SHA256[key], key


# ── Half 2: live Python-source side (skipped post-T9) ─────────────────────────


def _load_python_truth() -> dict[str, object] | None:
    """Derive the truth from the ACTUAL Python objects/loaders.

    Returns ``None`` (and the caller skips) if the sources have been removed
    (Task 9). Mirrors the exact Python derivation: SURNAMES verbatim string,
    COMPOUND_SURNAMES/SET frozensets, and the two ``_load_*`` loaders.
    """
    try:
        from argus_redact.lang.en.given_names import GIVEN_NAME_SET
        from argus_redact.lang.en.surnames import SURNAME_SET
        from argus_redact.lang.zh.person import (
            _load_common_words,
            _load_negative_dict,
        )
        from argus_redact.lang.zh.surnames import COMPOUND_SURNAMES, SURNAMES
    except (ImportError, FileNotFoundError):
        return None

    try:
        not_names = _load_negative_dict()
        common_words = _load_common_words()
    except FileNotFoundError:
        return None

    return {
        "surnames_zh": SURNAMES,
        "compound_surnames_zh": set(COMPOUND_SURNAMES),
        "not_names_zh": set(not_names),
        "common_words_zh": set(common_words),
        "given_names_en": set(GIVEN_NAME_SET),
        "surnames_en": set(SURNAME_SET),
    }


def test_python_source_matches_frozen_fingerprints():
    truth = _load_python_truth()
    if truth is None:
        pytest.skip("Python person-name sources removed (post-Task-9)")
    # Counts.
    assert len(set(truth["surnames_zh"])) == EXPECTED_COUNTS["surnames_zh"]
    for key in _LIST_POOLS:
        assert len(truth[key]) == EXPECTED_COUNTS[key], key
    # sha256.
    assert _sha_str(truth["surnames_zh"]) == EXPECTED_SHA256["surnames_zh"]
    for key in _LIST_POOLS:
        assert _sha_list(truth[key]) == EXPECTED_SHA256[key], key


def test_core_pools_equal_python_source():
    truth = _load_python_truth()
    if truth is None:
        pytest.skip("Python person-name sources removed (post-Task-9)")
    pools = _core_pools()
    # SURNAMES: exact string equality (byte-for-byte, order-load-bearing).
    assert pools["surnames_zh"] == truth["surnames_zh"]
    # All list pools: full membership comparison as sets (order-independent).
    for key in _LIST_POOLS:
        assert set(pools[key]) == truth[key], key


if __name__ == "__main__":
    # Convenience: print the live fingerprints so they can be re-frozen
    # on a deliberate source change (review the diff before updating).
    truth = _load_python_truth()
    if truth is None:
        raise SystemExit("Python sources unavailable; cannot recompute fingerprints.")
    print("EXPECTED_COUNTS = {")
    print(f'    "surnames_zh": {len(set(truth["surnames_zh"]))},')
    for key in _LIST_POOLS:
        print(f'    "{key}": {len(truth[key])},')
    print("}")
    print("EXPECTED_SHA256 = {")
    print(f'    "surnames_zh": "{_sha_str(truth["surnames_zh"])}",')
    for key in _LIST_POOLS:
        print(f'    "{key}": "{_sha_list(truth[key])}",')
    print("}")
