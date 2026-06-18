"""Data-hygiene tests for the English surname + given-name pools.

The pools now live in the Rust RON SSOT and are read via the ``_core``
accessors (the old ``lang/en/surnames.py`` / ``lang/en/given_names.py``
modules were deleted in v0.7.6 — their content is the RON SSOT).

Exact size + sha256 fingerprints are locked by
``test_person_data_parity.py``; this file keeps the structural invariants
(non-empty, no duplicates, capitalization) pointed at the live pools.
"""

import argus_redact._core as _core


class TestSurnameData:
    def test_no_duplicates(self):
        surnames = list(_core.person_surnames_en())
        assert len(set(surnames)) == len(surnames)

    def test_non_empty(self):
        assert len(list(_core.person_surnames_en())) > 0

    def test_capitalized(self):
        for name in list(_core.person_surnames_en())[:20]:  # spot-check first 20
            assert name[0].isupper(), f"Surname {name!r} not capitalized"


class TestGivenNameData:
    def test_no_duplicates(self):
        given = list(_core.person_given_names_en())
        assert len(set(given)) == len(given)

    def test_non_empty(self):
        assert len(list(_core.person_given_names_en())) > 0

    def test_capitalized(self):
        for name in list(_core.person_given_names_en())[:20]:  # spot-check first 20
            assert name[0].isupper(), f"Given name {name!r} not capitalized"
