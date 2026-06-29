"""Parity test: _core.self_ref_pronouns() must exactly match the canonical set.

This is the bit-identity gate for SELF_REF_PRONOUNS — the set feeds
_KEEP_WHITELIST in pure/replacer.py, so any silent divergence would change
keep-strategy behavior.
"""

import argus_redact._core as _core


def test_core_self_ref_pronouns_matches_frozen_set():
    # Captured from: python -c
    #   "from argus_redact.pure.grammar import SELF_REF_PRONOUNS; print(sorted(SELF_REF_PRONOUNS))"
    # ['I', 'me', 'mine', 'my', 'myself', 'our', 'ours', 'ourselves', 'us', 'we']
    EXPECTED = frozenset(
        {"I", "me", "mine", "my", "myself", "our", "ours", "ourselves", "us", "we"}
    )
    assert frozenset(_core.self_ref_pronouns()) == EXPECTED
