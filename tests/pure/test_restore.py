"""Tests for restore() — pure string replacement."""

import pytest

from argus_redact import restore


class TestRestoreBasic:
    """Core replacement behavior."""

    def test_single_pseudonym(self):
        assert restore("P-037是好人", {"P-037": "王五"}) == "王五是好人"

    def test_multiple_pseudonyms(self, sample_key):
        text = "P-037和P-012在[咖啡店]讨论了去[某公司]面试的事"
        result = restore(text, sample_key)
        assert result == "王五和张三在星巴克讨论了去阿里面试的事"

    def test_pseudonym_at_start(self):
        assert restore("P-037说了话", {"P-037": "王五"}) == "王五说了话"

    def test_pseudonym_at_end(self):
        assert restore("他是P-037", {"P-037": "王五"}) == "他是王五"

    def test_multiple_occurrences_of_same_pseudonym(self):
        assert restore("P-037和P-037", {"P-037": "王五"}) == "王五和王五"


class TestRestoreLongestFirst:
    """Longer replacements must match before shorter ones."""

    def test_longest_match_wins(self):
        key = {"[某公司]": "阿里", "[某公司总部]": "阿里西溪园区"}
        assert restore("[某公司总部]开会", key) == "阿里西溪园区开会"

    def test_short_key_not_triggered_inside_long_match(self):
        key = {"[某公司]": "阿里", "[某公司总部]": "阿里西溪园区"}
        # [某公司] should not match inside [某公司总部]
        result = restore("[某公司总部]和[某公司]", key)
        assert result == "阿里西溪园区和阿里"


class TestRestoreEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_text(self, sample_key):
        assert restore("", sample_key) == ""

    def test_empty_key(self):
        assert restore("any text", {}) == "any text"

    def test_empty_text_and_empty_key(self):
        assert restore("", {}) == ""

    def test_no_matching_pseudonyms(self):
        assert restore("P-999 is unknown", {"P-037": "王五"}) == "P-999 is unknown"

    def test_text_without_pseudonym_patterns(self):
        assert restore("普通文本没有假名", {"P-037": "王五"}) == "普通文本没有假名"

    def test_replacement_contains_pseudonym_like_chars(self):
        """Original contains 'P' — should not trigger re-matching."""
        key = {"P-037": "P先生"}
        assert restore("P-037说了话", key) == "P先生说了话"


class TestRestorePurity:
    """restore() must be deterministic — same input = same output."""

    def test_deterministic(self, sample_key):
        text = "P-037和P-012在[咖啡店]"
        assert restore(text, sample_key) == restore(text, sample_key)

    def test_does_not_mutate_key(self, sample_key):
        original_key = dict(sample_key)
        restore("P-037在[咖啡店]", sample_key)
        assert sample_key == original_key


class TestRestoreErrors:
    """Type errors and invalid inputs."""

    def test_bad_key_type_raises_type_error(self):
        with pytest.raises(TypeError):
            restore("text", 123)

    def test_none_key_raises_type_error(self):
        with pytest.raises(TypeError):
            restore("text", None)
