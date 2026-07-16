"""The guard must not trust a degenerate anchor nonce.

Provenance means "the model echoed our verification token back, as instructed —
on its own line at the end of the reply." A bare substring test (`nonce in text`)
let three degenerate nonces through, and `_strip_nonce` then destroyed or corrupted
the caller's text while the call reported a clean COMPLETE restore:

- an EMPTY nonce is a substring of everything, so provenance passed and
  `_strip_nonce(text, "")` sliced the whole text to "" (data destruction);
- a nonce that is an incidental substring of the text (a common character like
  "的") passed provenance, and `_strip_nonce` removed every occurrence of it;
- a None nonce raised an uncaught TypeError instead of failing closed.

All three must FAIL CLOSED: return the text un-restored, outcome BLOCKED, a
provenance_failed event — never destroy or corrupt it. Reachable over the HTTP
/restore endpoint, which reconstructs an anchor from a client-supplied nonce.
"""

from argus_redact import make_anchor, redact
from argus_redact.compose.anchor import Anchor
from argus_redact.pure.restore import restore


def _fixture():
    red, key = redact("张三的电话是13800138000", lang="zh", mode="fast")
    return red, key


def test_empty_nonce_fails_closed_not_destroys():
    red, key = _fixture()
    out, det = restore(
        red, key, guard=True, anchor=Anchor(nonce="", scope=frozenset(key)), detailed=True
    )
    assert out == red, f"empty nonce destroyed/altered the text: {out!r}"
    assert det["outcome"] == "blocked"
    assert any(e["reason_code"] == "provenance_failed" for e in det["security_events"])


def test_incidental_substring_nonce_fails_closed():
    red, key = _fixture()
    # "的" occurs naturally in the redacted text but was never echoed as a token.
    out, det = restore(
        red, key, guard=True, anchor=Anchor(nonce="的", scope=frozenset(key)), detailed=True
    )
    assert out == red, f"substring nonce corrupted the text: {out!r}"
    assert det["outcome"] == "blocked"
    assert any(e["reason_code"] == "provenance_failed" for e in det["security_events"])


def test_none_nonce_fails_closed_not_raises():
    red, key = _fixture()
    out, det = restore(
        red, key, guard=True, anchor=Anchor(nonce=None, scope=frozenset(key)), detailed=True
    )
    assert out == red
    assert det["outcome"] == "blocked"


def test_legit_trailing_echo_still_restores():
    red, key = _fixture()
    anchor = make_anchor(key)
    reply = red + "\n" + anchor.nonce  # the model echoed the token on its own trailing line
    out = restore(reply, key, guard=True, anchor=anchor)
    assert "13800138000" in out  # restored
    assert anchor.nonce not in out  # echo stripped


def test_legit_ownline_echo_midreply_still_restores():
    red, key = _fixture()
    anchor = make_anchor(key)
    reply = red + "\n" + anchor.nonce + "\nokay done"  # own-line echo, not last
    out = restore(reply, key, guard=True, anchor=anchor)
    assert "13800138000" in out
    assert anchor.nonce not in out


def test_short_suffix_nonce_fails_closed():
    # A short nonce that coincides with a text suffix (a masked phone ends "8000")
    # must not pass provenance and let _strip_nonce truncate the tail.
    red, key = _fixture()  # red ends with the masked phone "...138****8000"
    out, det = restore(
        red, key, guard=True, anchor=Anchor(nonce="8000", scope=frozenset(key)), detailed=True
    )
    assert out == red, f"short suffix nonce corrupted the text: {out!r}"
    assert det["outcome"] == "blocked"


def test_make_anchor_nonce_clears_floor():
    # Enforces the producer/consumer coupling: make_anchor's token must be at least
    # as long as the floor the guard rejects below, or every genuine nonce would
    # fail closed. A shrink of make_anchor's token_hex arg trips this, not prod.
    from argus_redact.pure.restore import _MIN_NONCE_LEN

    _red, key = redact("张三的电话是13800138000", lang="zh", mode="fast")
    assert len(make_anchor(key).nonce) >= _MIN_NONCE_LEN


def test_strip_nonce_refuses_degenerate_input_directly():
    # Defense in depth: _strip_nonce is a text-destroyer; called directly with a
    # degenerate nonce it must return the text untouched, not slice it away.
    from argus_redact.pure.restore import _strip_nonce

    assert _strip_nonce("keep this text", "") == "keep this text"
    assert _strip_nonce("keep this text", "的") == "keep this text"
    assert _strip_nonce("keep this text", None) == "keep this text"
