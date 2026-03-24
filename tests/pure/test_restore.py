"""Tests for restore() — pure string replacement."""

import pytest

from argus_redact import restore


class TestRestoreBasic:
    """Core replacement behavior."""

    def test_should_replace_single_pseudonym_when_key_has_one_entry(self):
        key = {"P-037": "王五"}
        text = "P-037是好人"

        result = restore(text, key)

        assert result == "王五是好人"

    def test_should_replace_all_pseudonyms_when_key_has_multiple_entries(self, sample_key):
        text = "P-037和P-012在[咖啡店]讨论了去[某公司]面试的事"

        result = restore(text, sample_key)

        assert result == "王五和张三在星巴克讨论了去阿里面试的事"

    def test_should_replace_pseudonym_when_at_start_of_text(self):
        key = {"P-037": "王五"}

        result = restore("P-037说了话", key)

        assert result == "王五说了话"

    def test_should_replace_pseudonym_when_at_end_of_text(self):
        key = {"P-037": "王五"}

        result = restore("他是P-037", key)

        assert result == "他是王五"

    def test_should_replace_all_occurrences_when_same_pseudonym_appears_twice(self):
        key = {"P-037": "王五"}

        result = restore("P-037和P-037", key)

        assert result == "王五和王五"


class TestRestoreLongestFirst:
    """Longer replacements must match before shorter ones."""

    def test_should_match_longer_key_when_short_key_is_prefix_of_long(self):
        key = {"[某公司]": "阿里", "[某公司总部]": "阿里西溪园区"}

        result = restore("[某公司总部]开会", key)

        assert result == "阿里西溪园区开会"

    def test_should_replace_both_when_long_and_short_keys_appear_separately(self):
        key = {"[某公司]": "阿里", "[某公司总部]": "阿里西溪园区"}

        result = restore("[某公司总部]和[某公司]", key)

        assert result == "阿里西溪园区和阿里"


class TestRestoreEdgeCases:
    """Edge cases and boundary conditions."""

    def test_should_return_empty_when_text_is_empty(self, sample_key):
        result = restore("", sample_key)

        assert result == ""

    def test_should_return_original_when_key_is_empty(self):
        result = restore("any text", {})

        assert result == "any text"

    def test_should_return_empty_when_both_empty(self):
        result = restore("", {})

        assert result == ""

    def test_should_leave_unknown_pseudonyms_when_not_in_key(self):
        key = {"P-037": "王五"}

        result = restore("P-999 is unknown", key)

        assert result == "P-999 is unknown"

    def test_should_return_original_when_no_pseudonym_patterns_in_text(self):
        key = {"P-037": "王五"}

        result = restore("普通文本没有假名", key)

        assert result == "普通文本没有假名"

    def test_should_not_re_match_when_original_contains_pseudonym_like_chars(self):
        key = {"P-037": "P先生"}

        result = restore("P-037说了话", key)

        assert result == "P先生说了话"


class TestRestorePurity:
    """restore() must be deterministic — same input = same output."""

    def test_should_return_same_result_when_called_twice(self, sample_key):
        text = "P-037和P-012在[咖啡店]"

        result1 = restore(text, sample_key)
        result2 = restore(text, sample_key)

        assert result1 == result2

    def test_should_not_mutate_key_when_restoring(self, sample_key):
        original_key = dict(sample_key)

        restore("P-037在[咖啡店]", sample_key)

        assert sample_key == original_key


class TestRestoreErrors:
    """Type errors and invalid inputs."""

    def test_should_raise_type_error_when_key_is_int(self):
        with pytest.raises(TypeError):
            restore("text", 123)

    def test_should_raise_type_error_when_key_is_none(self):
        with pytest.raises(TypeError):
            restore("text", None)
