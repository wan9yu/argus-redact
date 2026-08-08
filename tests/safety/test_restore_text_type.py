"""``restore()`` type-checks ``key`` but never typed-checked ``text``.

The v0.8.0 fail-closed branch (guard on, no anchor) returns before any Rust
call, so a non-``str`` ``text`` sailed through and came back as the "restored"
value — a success envelope wrapping the caller's garbage. The anchored branch
does reject it, from deep inside PyO3, so the same input succeeded or failed
depending on whether an anchor happened to be present.
"""

from __future__ import annotations

import pytest

NON_STR = [{"a": 1}, ["a"], 5, 3.5, True, None, b"bytes"]


@pytest.mark.parametrize("text", NON_STR)
def test_restore_rejects_non_str_text_unguarded(text):
    from argus_redact.pure.restore import restore

    with pytest.raises(TypeError, match="text must be a string"):
        restore(text, {"P-1": "Alice"}, guard=False)


@pytest.mark.parametrize("text", NON_STR)
def test_restore_rejects_non_str_text_guarded_no_anchor(text):
    """The fail-closed branch is exactly where the check was missing."""
    from argus_redact.pure.restore import restore

    with pytest.raises(TypeError, match="text must be a string"):
        restore(text, {"P-1": "Alice"}, guard=True)


def test_restore_rejects_non_str_text_before_the_empty_key_shortcut():
    """An empty key must not buy an exemption — /restore's default is key={}."""
    from argus_redact.pure.restore import restore

    with pytest.raises(TypeError, match="text must be a string"):
        restore(["a"], {}, guard=False)


def test_restore_str_text_still_restores():
    """Positive control."""
    from argus_redact.pure.restore import restore

    assert restore("hello P-1", {"P-1": "Alice"}, guard=False) == "hello Alice"
