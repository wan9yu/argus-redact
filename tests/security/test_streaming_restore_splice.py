"""The bounded-drain cut must never manufacture a token boundary.

``StreamingRestorer``'s force-flush emits ``buffer[:cut]`` and keeps
``buffer[cut:]``. The restore matcher is digit-bounded: a numeric fake may not
match inside a longer run of digits. But the cut ends a string — so if it lands
inside a digit run, the surviving half starts at position 0 and the digit that
was blocking the match has already been emitted. The fake then matches, and the
ORIGINAL value it stands for is spliced into the middle of an unrelated number.

One-shot restore of the same text refuses. Streaming must give the same answer.
"""

import warnings

import pytest

from argus_redact.streaming import DEFAULT_MAX_BUFFER, StreamingRestorer

# A numeric fake standing for a real phone number — what the mask and
# pseudonym strategies produce for numeric types.
KEY = {"12345": "13800138000"}

# A boundary-free stretch past max_buffer (a base64 blob, a code block, one
# long JSON line) followed by an unrelated number that CONTAINS the fake.
FILLER = "x" * (DEFAULT_MAX_BUFFER - 2)
TAIL = "9912345 and then some more words here"
WHOLE = FILLER + TAIL


def _drive(chunks, strategy="sentence"):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = StreamingRestorer(dict(KEY), strategy=strategy)
        out = "".join(r.feed(c) for c in chunks)
        return out + r.flush()


def test_one_shot_restore_refuses_the_embedded_numeric_fake():
    """Control: the digit bound does its job when nothing is cut."""
    out = _drive([WHOLE], strategy="none")
    assert "13800138000" not in out
    assert out == WHOLE


@pytest.mark.parametrize("cut_at", range(DEFAULT_MAX_BUFFER - 2, DEFAULT_MAX_BUFFER + 6))
def test_force_flush_cut_never_splices_pii_into_an_unrelated_number(cut_at):
    out = _drive([WHOLE[:cut_at], WHOLE[cut_at:]])
    assert "13800138000" not in out, (
        f"cut at {cut_at} manufactured a digit boundary and spliced the original "
        f"phone number into an unrelated one: {out[-46:]!r}"
    )
    assert out == WHOLE, "the stream must reassemble byte-for-byte"


def test_strategy_none_reassembles_byte_for_byte_across_the_hold():
    """``none`` flushes per chunk, but not per chunk IN ISOLATION.

    It routes through the same straddle scan as the sentence strategy, so a
    chunk that ends on a complete fake is held until the next character is
    known — otherwise the cut manufactures the very token boundary this file
    is about. The guarantee is therefore about the CONCATENATION, not about
    which chunk each character comes out on: nothing is lost, nothing is
    duplicated, and every pseudonym is restored exactly once.
    """
    chunks = ["abc ", "P-1", " def"]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = StreamingRestorer({"P-1": "Alice"}, strategy="none")
        outs = [r.feed(c) for c in chunks]
        outs.append(r.flush())
    assert "".join(outs) == "abc Alice def"
    # Every chunk is a prefix-extension of what came before — the stream only
    # ever appends, it never rewrites text it already emitted.
    assert "P-1" not in "".join(outs)


def test_the_drain_still_makes_forward_progress_on_an_all_digit_blob():
    """A digit run longer than the whole buffer must not stall the stream."""
    blob = "7" * (DEFAULT_MAX_BUFFER * 3)
    out = _drive([blob[:i] for i in ()] or [blob[: len(blob) // 2], blob[len(blob) // 2 :]])
    assert out == blob
