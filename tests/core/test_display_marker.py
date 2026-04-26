"""Tests for display marker config + helpers."""

from argus_redact.pure.display_marker import (
    DEFAULT_DISPLAY_MARKER,
    DISPLAY_MARKER_PRESETS,
    mark_for_display,
    resolve_marker,
    strip_display_markers,
)
from argus_redact.pure.restore import restore


class TestDisplayMarkerPresets:
    def test_default_should_be_circled_f(self):
        assert DEFAULT_DISPLAY_MARKER == "ⓕ"

    def test_presets_should_include_known_keys(self):
        for key in ("circled_f", "superscript_s", "asterisk", "chinese", "none"):
            assert key in DISPLAY_MARKER_PRESETS

    def test_resolve_should_accept_preset_name(self):
        assert resolve_marker("circled_f") == "ⓕ"
        assert resolve_marker("chinese") == "(假)"

    def test_resolve_should_accept_literal_string(self):
        assert resolve_marker("§") == "§"

    def test_resolve_should_default_to_circled_f_on_none(self):
        assert resolve_marker(None) == "ⓕ"

    def test_resolve_should_return_empty_for_none_preset(self):
        assert resolve_marker("none") == ""


class TestMarkForDisplay:
    def test_should_append_marker_to_each_fake_value(self):
        downstream = "请拨打 19999123456 联系张明"
        key = {"19999123456": "13912345678", "张明": "王建国"}
        result = mark_for_display(downstream, key, marker="ⓕ")
        assert result == "请拨打 19999123456ⓕ 联系张明ⓕ"

    def test_should_not_double_mark(self):
        downstream = "19999123456ⓕ"
        key = {"19999123456": "x"}
        result = mark_for_display(downstream, key, marker="ⓕ")
        assert result == "19999123456ⓕ"  # idempotent

    def test_should_prefer_longest_match_to_avoid_prefix_collision(self):
        downstream = "张明和张在场"
        key = {"张明": "x", "张": "y"}
        result = mark_for_display(downstream, key, marker="ⓕ")
        assert result == "张明ⓕ和张ⓕ在场"

    def test_should_default_marker_when_none(self):
        downstream = "联系张明"
        key = {"张明": "x"}
        result = mark_for_display(downstream, key)
        assert result == "联系张明ⓕ"

    def test_should_return_text_unchanged_when_marker_is_none_preset(self):
        downstream = "联系张明"
        key = {"张明": "x"}
        result = mark_for_display(downstream, key, marker="none")
        assert result == downstream

    def test_should_return_text_unchanged_when_key_is_empty(self):
        downstream = "联系张明"
        result = mark_for_display(downstream, {}, marker="ⓕ")
        assert result == downstream


class TestStripDisplayMarkers:
    def test_should_remove_marker_from_fake_values(self):
        marked = "请拨打 19999123456ⓕ 联系张明ⓕ"
        result = strip_display_markers(marked, marker="ⓕ")
        assert result == "请拨打 19999123456 联系张明"

    def test_should_be_inverse_of_mark(self):
        downstream = "联系 张明 拨 19999123456"
        key = {"张明": "x", "19999123456": "y"}
        marked = mark_for_display(downstream, key, marker="ⓕ")
        assert strip_display_markers(marked, marker="ⓕ") == downstream

    def test_should_default_marker_when_none(self):
        marked = "张明ⓕ"
        result = strip_display_markers(marked)
        assert result == "张明"

    def test_should_return_text_unchanged_when_marker_is_none_preset(self):
        marked = "张明ⓕ"
        result = strip_display_markers(marked, marker="none")
        assert result == marked

    def test_should_return_text_unchanged_when_marker_absent(self):
        text = "联系张明"
        result = strip_display_markers(text, marker="ⓕ")
        assert result == text


class TestRestoreWithMarkers:
    def test_restore_should_strip_markers_before_lookup(self):
        marked = "请拨打 19999123456ⓕ 联系 张明ⓕ"
        key = {"19999123456": "13912345678", "张明": "王建国"}
        result = restore(marked, key, display_marker="ⓕ")
        assert result == "请拨打 13912345678 联系 王建国"

    def test_restore_should_handle_word_boundary_extension(self):
        """LLM may rewrite '张明' -> '张明先生'; restore matches '张明' inside the longer phrase."""
        text = "张明先生今天到了"
        key = {"张明": "王建国"}
        result = restore(text, key)
        assert result == "王建国先生今天到了"

    def test_restore_should_be_noop_when_marker_absent_in_text(self):
        text = "请拨打 19999123456 联系 张明"
        key = {"19999123456": "13912345678", "张明": "王建国"}
        result = restore(text, key, display_marker="ⓕ")
        assert result == "请拨打 13912345678 联系 王建国"

    def test_restore_should_handle_empty_key_with_marker(self):
        marked = "纯文本ⓕ"
        result = restore(marked, {}, display_marker="ⓕ")
        assert result == "纯文本"

    def test_restore_should_default_marker_when_none_passed(self):
        # display_marker=None means no stripping at all (default behavior)
        text = "张明ⓕ"
        key = {"张明": "王建国"}
        result = restore(text, key)
        # Without display_marker, the ⓕ stays attached to the lookup target,
        # so 张明 is still replaced but the trailing ⓕ remains.
        assert result == "王建国ⓕ"
