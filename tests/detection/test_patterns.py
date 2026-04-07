"""Tests for match_patterns() pure function."""

from argus_redact.pure.patterns import match_patterns


class TestMatchPatternsReturn:
    """Return type and structure."""

    def test_should_return_list_when_no_patterns(self):
        results, _ = match_patterns("text", [])

        assert isinstance(results, list)

    def test_should_return_empty_when_patterns_list_is_empty(self):
        results, _ = match_patterns("13812345678", [])

        assert results == []

    def test_should_return_empty_when_text_is_empty(self):
        pattern = {"type": "phone", "label": "[手机号]", "pattern": r"1[3-9]\d{9}"}

        results, _ = match_patterns("", [pattern])

        assert results == []

    def test_should_include_all_fields_when_pattern_matches(self):
        pattern = {"type": "test", "label": "[test]", "pattern": r"\d+"}

        results, _ = match_patterns("abc123def", [pattern])

        assert len(results) == 1
        r = results[0]
        assert r.text == "123"
        assert r.type == "test"
        assert r.start == 3
        assert r.end == 6
        assert r.confidence == 1.0

    def test_should_sort_by_position_when_multiple_matches(self):
        pattern = {"type": "num", "label": "[num]", "pattern": r"\d+"}

        results, _ = match_patterns("a111b222c333", [pattern])

        assert len(results) == 3
        assert results[0].start < results[1].start < results[2].start

    def test_should_filter_out_when_validate_returns_false(self):
        pattern = {
            "type": "even",
            "label": "[even]",
            "pattern": r"\d+",
            "validate": lambda s: int(s) % 2 == 0,
        }

        results, _ = match_patterns("a13b24c", [pattern])

        assert len(results) == 1
        assert results[0].text == "24"
