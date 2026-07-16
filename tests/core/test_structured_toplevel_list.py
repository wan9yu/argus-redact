"""R2 — redact_json on a top-level list with a ``[*].path`` pattern.

``_parse_paths`` turns ``"[*].phone"`` into ``".*".split(".")`` = ``['', '*',
'phone']`` — a leading EMPTY segment from the literal ``[*]`` prefix. A
top-level list leaf's walk-path never carries that empty prefix, so the path
never matches and nothing gets redacted: silent zero-redaction with a
success return (the caller sees 200/no error, PII stays in the output).
"""

import pytest

from argus_redact.structured import redact_json


class TestPathsBareStrRejected:
    # F8 (v0.8.2): a bare str for `paths` (e.g. "messages" instead of
    # ["messages"]) iterates char-by-char in _parse_paths, matches nothing,
    # and returns success with zero redaction — a silent leak. Must raise.
    def test_should_raise_typeerror_for_bare_str_paths(self):
        data = {"messages": "call me at 13812345678"}
        with pytest.raises(TypeError):
            redact_json(data, paths="messages", mode="fast", salt=42)

    def test_should_still_redact_with_list_paths(self):
        data = {"messages": "call me at 13812345678"}
        redacted, key = redact_json(data, paths=["messages"], mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert "13812345678" in key.values()


class TestTopLevelListBracketStarPath:
    def test_should_redact_toplevel_list_with_bracket_star_path(self):
        data = [{"name": "张伟", "phone": "13812345678"}]
        redacted, key = redact_json(data, paths=["[*].phone"], mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert "13812345678" in key.values()

    def test_should_redact_toplevel_list_bracket_star_matches_dotstar_result(self):
        # `*.phone` (no brackets) already worked — confirm both forms now agree.
        data = [{"name": "张伟", "phone": "13812345678"}]
        bracket_redacted, bracket_key = redact_json(data, paths=["[*].phone"], mode="fast", salt=42)
        star_redacted, star_key = redact_json(data, paths=["*.phone"], mode="fast", salt=42)

        assert bracket_redacted == star_redacted
        assert bracket_key == star_key

    def test_should_still_redact_nested_bracket_star_path(self):
        # Regression guard: the fix must not break the already-working nested case.
        data = {"messages": [{"role": "user", "content": "call me at 13812345678"}]}
        redacted, key = redact_json(data, paths=["messages[*].content"], mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert "13812345678" in key.values()

    def test_should_redact_toplevel_list_of_lists_bracket_star_path(self):
        # Nested top-level-list case: list of lists, leaf reached via [*].[*].phone.
        data = [[{"name": "张伟", "phone": "13812345678"}]]
        redacted, key = redact_json(data, paths=["[*].[*].phone"], mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert "13812345678" in key.values()
