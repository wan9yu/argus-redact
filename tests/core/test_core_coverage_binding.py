"""The _core.restore_lost_coverage binding — the shared primitive both Rust
pipelines and the Python glue use to hold the post-merge coverage invariant."""

from argus_redact import _core


def _pm(text, type_, start, end):
    # NOTE: the Rust kwarg is `type_`, the attribute read back is `.type`.
    return _core.PatternMatch(text, type_, start, end, 1.0, 1)


def test_returns_filtered_untouched_when_nothing_was_lost():
    phone = _pm("13800138000", "phone", 15, 26)
    out, restored = _core.restore_lost_coverage(
        [phone], [(15, 26)], [phone], None, None, False, "irrelevant"
    )
    assert [(e.text, e.type) for e in out] == [("13800138000", "phone")]
    assert restored == []


def test_restores_a_phone_absorbed_by_a_type_filtered_winner():
    phone = _pm("13800138000", "phone", 15, 26)
    med = _pm("number 13800138000", "medical", 8, 26)
    out, restored = _core.restore_lost_coverage(
        [phone, med],
        [(8, 26)],
        [],
        ["phone"],
        None,
        False,
        "Contact number 13800138000 for details",
    )
    assert [(e.text, e.type) for e in out] == [("13800138000", "phone")]
    assert restored == ["phone"]


def test_does_not_restore_an_entity_the_filter_itself_excludes():
    sr = _pm("我们", "self_reference", 11, 13)
    out, restored = _core.restore_lost_coverage(
        [sr], [(11, 13)], [], None, None, True, "今天天气不错我们出去走走"
    )
    assert out == []
    assert restored == []
