"""restore() must fail closed on a corrupted/hand-built key with an
empty-string entry, not explode the original throughout the text.

argus never produces a key entry whose surrogate is `""` — the redact-side
producer (`replace.rs`) explicitly refuses to register an empty replacement,
because an empty surrogate matches between every character of the text on
restore, splicing the original in everywhere it "matches". A `{"": "..."}`
key can therefore only arrive via corruption or hand-building, and restore
must reject it rather than execute the explosion.
"""

import pytest

from argus_redact.pure.restore import restore
from argus_redact.streaming import StreamingRestorer
from argus_redact.structured import restore_csv, restore_json


def test_empty_string_key_entry_raises_not_explodes():
    with pytest.raises(ValueError, match="empty"):
        restore("abc", {"": "SECRET"}, guard=False)


def test_valid_key_still_restores():
    assert restore("call PHONE-1", {"PHONE-1": "13800138000"}, guard=False) == "call 13800138000"


def test_empty_string_key_entry_raises_via_restore_json():
    # restore_json/restore_csv/StreamingRestorer all route their substitution
    # through the same core restore() — the rejection must fire through each
    # entry point, not just the pure.restore.restore call site tested above.
    with pytest.raises(ValueError, match="empty"):
        restore_json({"note": "abc"}, {"": "SECRET"})


def test_empty_string_key_entry_raises_via_restore_csv():
    with pytest.raises(ValueError, match="empty"):
        restore_csv("abc\n", {"": "SECRET"})


def test_empty_string_key_entry_raises_via_streaming_restorer():
    restorer = StreamingRestorer({"": "SECRET"}, strategy="none")
    with pytest.raises(ValueError, match="empty"):
        restorer.feed("abc")


def test_empty_string_alias_also_raises():
    # An empty-string ALIAS (not just an empty key) is equally corrupt: it merges
    # into the flat lookup and would reach the alternation the same way. The
    # rejection must catch it too — the core guard runs against the post-merge map.
    with pytest.raises(ValueError, match="empty"):
        restore("P-1 came home.", {"P-1": "Zhang San"}, aliases={"P-1": [""]}, guard=False)
