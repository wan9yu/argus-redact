"""The scope guard may WITHHOLD an identity — it may never SPLICE one.

Python-level mirror of the core's `restore::tests::guarded_withheld_*` cases.
The core filtered out-of-scope entries out of the key before building the
longest-first alternation, so a withheld pseudonym had no alternative of its
own and a SHORTER in-scope one matched inside it. Turning the guard on
produced a corrupted mixed identity that the guard simultaneously reported as
"withheld" — worse than leaving the guard off.
"""

from __future__ import annotations

import pytest

from argus_redact.compose.anchor import Anchor, make_anchor
from argus_redact.pure.restore import restore


def _anchor(key, scope):
    """An anchor over a NARROWER scope than the key — what a multi-turn
    compose flow produces. `make_anchor` always scopes to the whole key, so the
    nonce is borrowed from it and the scope narrowed explicitly."""
    return Anchor(nonce=make_anchor(key).nonce, scope=frozenset(scope))


@pytest.mark.filterwarnings("ignore::argus_redact.exceptions.SecurityWarning")
def test_withheld_prefix_code_is_not_spliced_by_a_shorter_in_scope_code():
    key = {"P-1": "Alice", "P-10": "Ten"}
    anchor = _anchor(key, ["P-1"])

    text, meta = restore(f"P-10 and P-1.\n{anchor.nonce}", key, anchor=anchor, detailed=True)

    assert text == "P-10 and Alice."
    assert "Alice0" not in text, "the withheld token was consumed by a shorter in-scope match"
    assert meta["outcome"] == "partial"


@pytest.mark.filterwarnings("ignore::argus_redact.exceptions.SecurityWarning")
def test_withheld_realistic_fake_is_not_spliced_when_fakes_share_a_prefix():
    # 王芳 is a strict prefix of 王芳华, so the withheld 王芳华 used to be
    # rewritten into 张伟华 — a person who exists in neither record.
    key = {"王芳": "张伟", "王芳华": "李明"}
    anchor = _anchor(key, ["王芳"])

    text, meta = restore(
        f"王芳华 reported that 王芳 left.\n{anchor.nonce}", key, anchor=anchor, detailed=True
    )

    assert text == "王芳华 reported that 张伟 left."
    assert "张伟华" not in text
    assert meta["outcome"] == "partial"


@pytest.mark.filterwarnings("ignore::argus_redact.exceptions.SecurityWarning")
def test_guarded_in_scope_substitutions_equal_the_unguarded_ones():
    """Whatever the guard DOES substitute must be byte-identical to the
    unguarded result; only the withheld tokens may differ."""
    key = {"P-1": "Alice", "P-10": "Ten", "P-100": "Hundred"}
    anchor = _anchor(key, ["P-1", "P-100"])

    guarded, _ = restore(f"P-100 P-10 P-1\n{anchor.nonce}", key, anchor=anchor, detailed=True)
    unguarded = restore("P-100 P-10 P-1", key, guard=False)

    assert guarded == "Hundred P-10 Alice"
    assert unguarded == "Hundred Ten Alice"


@pytest.mark.filterwarnings("ignore::argus_redact.exceptions.SecurityWarning")
def test_alias_may_not_claim_an_out_of_scope_fakes_slot():
    """The alias map was merged over the ALREADY-SCOPED key, so an alias of an
    in-scope fake found the out-of-scope fake's slot empty and took it — the
    out-of-scope pseudonym was substituted with the wrong identity, and the
    collision `strict=True` exists to raise on was never recorded."""
    key = {"P-1": "Alice", "P-2": "Bob"}
    anchor = _anchor(key, ["P-1"])

    text, meta = restore(
        f"P-1 and P-2.\n{anchor.nonce}",
        key,
        aliases={"P-1": ("P-2",)},
        anchor=anchor,
        detailed=True,
    )

    assert text == "Alice and P-2."
    assert text != "Alice and Alice."
    codes = {event["reason_code"] for event in meta["security_events"]}
    assert "alias_collision" in codes, meta


@pytest.mark.filterwarnings("ignore::argus_redact.exceptions.SecurityWarning")
def test_alias_of_an_out_of_scope_fake_is_withheld():
    key = {"P-1": "Alice", "P-2": "Bob"}
    anchor = _anchor(key, ["P-1"])

    text, meta = restore(
        f"P-1 met Bobby.\n{anchor.nonce}",
        key,
        aliases={"P-2": ("Bobby",)},
        anchor=anchor,
        detailed=True,
    )

    assert text == "Alice met Bobby."
    assert meta["outcome"] == "partial"
