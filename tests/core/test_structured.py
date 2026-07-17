"""Tests for structured data redaction — JSON (flat, nested, paths) and CSV."""

import csv
import io

import pytest

from argus_redact import SecurityWarning
from argus_redact.structured import redact_csv, redact_json, restore_csv, restore_json

# ══════════════════════════════════════════════════════════════
# JSON — basic
# ══════════════════════════════════════════════════════════════


class TestRedactJSON:
    def test_should_redact_flat_dict(self):
        data = {"name": "张三", "phone": "13812345678", "age": 30}
        redacted, key = redact_json(data, mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert redacted["age"] == 30

    def test_should_redact_nested_dict(self):
        data = {"user": {"name": "张三", "contact": {"phone": "13812345678"}}, "action": "login"}
        redacted, key = redact_json(data, mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert redacted["action"] == "login"

    def test_should_redact_list_of_dicts(self):
        data = [
            {"name": "张三", "phone": "13812345678"},
            {"name": "李四", "phone": "15900001234"},
        ]
        redacted, key = redact_json(data, mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert "15900001234" not in str(redacted)

    def test_should_roundtrip_json(self):
        data = {"text": "电话13812345678，邮箱zhang@test.com"}
        redacted, key = redact_json(data, mode="fast", salt=42)
        restored = restore_json(redacted, key)

        assert "13812345678" in str(restored)
        assert "zhang@test.com" in str(restored)


# ════════════════════════════════════════════════════════════���═
# JSON — with_types
# ══════════════════════════════════════════════════════════════


class TestRedactJsonWithTypes:
    def test_should_return_type_map_when_with_types(self):
        data = {"phone": "手机13812345678"}
        redacted, key, types = redact_json(data, mode="fast", salt=42, with_types=True)

        assert "13812345678" not in str(redacted)
        assert isinstance(types, dict)
        assert any(v == "phone" for v in types.values())

    def test_should_return_2_tuple_when_no_with_types(self):
        data = {"phone": "13812345678"}
        result = redact_json(data, mode="fast", salt=42)

        assert len(result) == 2

    def test_should_aggregate_types_across_fields(self):
        data = {
            "phone": "手机13812345678",
            "id": "身份证110101199003074610",
        }
        redacted, key, types = redact_json(data, mode="fast", salt=42, with_types=True)

        type_values = set(types.values())
        assert "phone" in type_values
        assert "id_number" in type_values

    def test_should_work_with_paths_and_with_types(self):
        data = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "手机13812345678"}],
        }
        redacted, key, types = redact_json(
            data,
            paths=["messages[*].content"],
            mode="fast",
            salt=42,
            with_types=True,
        )

        assert redacted["model"] == "gpt-4o"
        assert any(v == "phone" for v in types.values())


# ══════════════════════════════════════════════════════════════
# JSON — selective paths
# ══════════════════════════════════════════════════════════════


class TestRedactJsonPaths:
    def test_should_redact_only_specified_paths(self):
        data = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "张三的手机13812345678"},
            ],
        }
        result, key = redact_json(data, paths=["messages[*].content"], mode="fast")

        assert result["model"] == "gpt-4o"
        assert result["messages"][0]["role"] == "system"
        assert "13812345678" not in result["messages"][1]["content"]

    def test_should_redact_nested_path(self):
        data = {"user": {"name": "张三", "phone": "13812345678", "id": 123}}
        result, key = redact_json(data, paths=["user.phone"], mode="fast")

        assert result["user"]["name"] == "张三"
        assert "13812345678" not in result["user"]["phone"]
        assert result["user"]["id"] == 123

    def test_should_redact_all_when_no_paths(self):
        data = {"name": "张三", "phone": "13812345678"}
        result, key = redact_json(data, mode="fast")

        assert "13812345678" not in str(result)

    def test_should_handle_wildcard_in_list(self):
        data = {
            "items": [
                {"text": "手机13812345678", "type": "message"},
                {"text": "身份证110101199003074610", "type": "id"},
            ]
        }
        result, key = redact_json(data, paths=["items[*].text"], mode="fast")

        assert result["items"][0]["type"] == "message"
        assert "13812345678" not in result["items"][0]["text"]
        assert "110101199003074610" not in result["items"][1]["text"]

    def test_should_handle_multiple_paths(self):
        data = {
            "sender": "张三",
            "receiver": "李四",
            "content": "手机13812345678",
            "timestamp": "2026-01-01",
        }
        result, key = redact_json(data, paths=["sender", "content"], mode="fast")

        assert result["receiver"] == "李四"
        assert result["timestamp"] == "2026-01-01"
        assert "13812345678" not in result["content"]

    def test_should_restore_paths_redacted_json(self):
        data = {"messages": [{"role": "user", "content": "手机13812345678"}]}
        redacted, key = redact_json(data, paths=["messages[*].content"], mode="fast", salt=42)
        restored = restore_json(redacted, key)

        assert "13812345678" in restored["messages"][0]["content"]

    def test_should_handle_nonexistent_path(self):
        data = {"name": "张三"}
        result, key = redact_json(data, paths=["nonexistent.field"], mode="fast")

        assert result["name"] == "张三"
        assert len(key) == 0

    def test_should_redact_block_form_content_under_scoped_path(self):
        # The Anthropic/OpenAI block form
        # content=[{"type":"text","text":...}] must be redacted when scoping to
        # messages[*].content. The leaf sits at depth 5; an exact-depth gate
        # silently skips it and leaks the PII. Scoping to a path means "this
        # subtree", so every string leaf below it must be redacted.
        data = {
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "张三的手机13812345678"}],
                }
            ]
        }
        result, key = redact_json(data, paths=["messages[*].content"], mode="fast", salt=42)

        leaf = result["messages"][0]["content"][0]["text"]
        assert "13812345678" not in leaf
        assert len(key) >= 1


# ══════════════════════════════════════════════════════════════
# Cross-leaf / cross-cell alias-key regression
# ══════════════════════════════════════════════════════════════


class TestCrossLeafAliasKey:
    """A repeated entity across multiple JSON leaves or CSV cells must map to one alias.

    These tests guard against a `key=None`-per-leaf refactor that would assign a
    fresh (dangling) alias for every occurrence — breaking cross-leaf restore and
    obscuring the shared key with spurious duplicates.
    """

    def test_repeated_entity_across_json_leaves_maps_to_one_alias(self):
        """Same phone in two JSON leaves → identical alias + single key entry."""
        data = {
            "message1": "电话13812345678",
            "message2": "再次确认，电话13812345678",
        }
        redacted, key = redact_json(data, mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        # One key entry for the one unique PII value
        assert len(key) == 1, f"Expected 1 key entry for one unique phone, got {len(key)}: {key}"
        # Both leaves carry the same alias
        alias = next(iter(key))
        assert alias in redacted["message1"], "alias absent from first leaf"
        assert alias in redacted["message2"], "alias absent from second leaf"

    def test_repeated_entity_across_json_leaves_restores_fully(self):
        """restore_json recovers the original phone from both leaves."""
        data = {
            "first": "电话13812345678",
            "second": "再次确认，电话13812345678",
        }
        redacted, key = redact_json(data, mode="fast", salt=42)
        restored = restore_json(redacted, key)

        assert "13812345678" in restored["first"]
        assert "13812345678" in restored["second"]

    def test_repeated_entity_across_csv_cells_maps_to_one_alias(self):
        """Same phone in two CSV cells → identical alias + single key entry."""
        csv_text = "col1,col2\n电话13812345678,再次确认13812345678"
        redacted_csv, key = redact_csv(csv_text, mode="fast", salt=42, has_header=True)

        assert "13812345678" not in redacted_csv
        assert len(key) == 1, f"Expected 1 key entry for one unique phone, got {len(key)}: {key}"

    def test_repeated_entity_across_csv_cells_restores_fully(self):
        """restore_csv recovers the original phone from both cells."""
        csv_text = "col1,col2\n电话13812345678,再次确认13812345678"
        redacted_csv, key = redact_csv(csv_text, mode="fast", salt=42, has_header=True)
        restored = restore_csv(redacted_csv, key)

        assert "13812345678" in restored

    def test_distinct_entities_across_csv_cells_accumulate_key(self):
        """Two DISTINCT PII values in separate CSV cells → key has 2 entries + both restore.

        Non-vacuity: a broken per-cell accumulation that resets the key dict before
        processing each cell would end up with only the last cell's entry (len==1) and
        fail to restore the phone from the first cell — this test catches that bug
        while the same-PII tests above cannot.
        """
        csv_text = "phone,id\n13812345678,110101199003074610"
        redacted_csv, key = redact_csv(csv_text, mode="fast", salt=42, has_header=True)

        assert "13812345678" not in redacted_csv
        assert "110101199003074610" not in redacted_csv
        assert len(key) == 2, (
            f"Expected 2 key entries for 2 distinct PII values, got {len(key)}: {key}"
        )
        restored = restore_csv(redacted_csv, key)
        assert "13812345678" in restored, "phone not restored from CSV cell"
        assert "110101199003074610" in restored, "id number not restored from CSV cell"

    def test_distinct_entities_across_json_leaves_accumulate_key(self):
        """Two DISTINCT PII values in separate JSON leaves → key has 2 entries + both restore.

        Non-vacuity: a broken per-leaf accumulation that resets the key dict before
        processing each leaf would end up with only the last leaf's entry (len==1) and
        fail to restore the phone from the first leaf — this test catches that bug
        while the same-PII tests above cannot.
        """
        data = {
            "contact": "电话13812345678",
            "identity": "身份证110101199003074610",
        }
        redacted, key = redact_json(data, mode="fast", salt=42)

        assert "13812345678" not in str(redacted)
        assert "110101199003074610" not in str(redacted)
        assert len(key) == 2, (
            f"Expected 2 key entries for 2 distinct PII values, got {len(key)}: {key}"
        )
        restored = restore_json(redacted, key)
        assert "13812345678" in str(restored), "phone not restored from JSON leaf"
        assert "110101199003074610" in str(restored), "id number not restored from JSON leaf"


# ══════════════════════════════════════════════════════════════
# CSV
# ══════════════════════════════════════════════════════════════


class TestRedactCSV:
    def test_should_redact_csv_string(self):
        csv_text = "name,phone\n张三,13812345678\n李四,15900001234"
        redacted, key = redact_csv(csv_text, mode="fast", salt=42)

        assert "13812345678" not in redacted
        assert "15900001234" not in redacted

    def test_should_preserve_headers(self):
        csv_text = "name,phone\n张三,13812345678"
        redacted, key = redact_csv(csv_text, mode="fast", salt=42)

        assert redacted.startswith("name,phone")

    def test_should_roundtrip_csv(self):
        csv_text = "name,phone\n张三,13812345678"
        redacted, key = redact_csv(csv_text, mode="fast", salt=42)
        restored = restore_csv(redacted, key)

        assert "13812345678" in restored

    def test_should_redact_first_row_when_headerless(self):
        # A headerless CSV must not leak its first data
        # row. With has_header=False every row is data and must be redacted.
        csv_text = "张三,13812345678\n李四,15900001234"
        redacted, key = redact_csv(csv_text, has_header=False, mode="fast", salt=42)

        assert "13812345678" not in redacted
        assert "15900001234" not in redacted

    def test_should_warn_when_preserved_header_carries_pii(self):
        # Default has_header=True preserves row 0. If that
        # row actually carries detectable PII the caller likely passed a
        # headerless CSV and is silently leaking it — warn loudly.
        csv_text = "张三,13812345678\n李四,15900001234"
        # match= pins this to the header warning — a high-entropy salt avoids the
        # unrelated low-entropy-salt SecurityWarning masking a vacuous pass.
        with pytest.warns(SecurityWarning, match="header"):
            redact_csv(csv_text, mode="fast", salt=bytes(range(32)))

    def test_restore_csv_preserves_row_structure_when_restored_value_has_comma(self):
        """A restored original value containing a comma must not split its cell.

        Neither the fast-mode regex layer nor NER (unavailable in this
        environment) reliably tags a comma-formatted name like "Smith, John"
        as PII, so the key is hand-constructed here to isolate the exact
        defect: restore_csv's OWN handling of a comma'd value, independent of
        detection. The old blind whole-string substring restore spliced the
        unescaped comma straight into the flat CSV text, turning one 2-column
        data row into 3 columns on re-parse — silent structural corruption.
        """
        redacted_csv = "name,city\n__NAME_TOKEN__,Boston"
        key = {"__NAME_TOKEN__": "Smith, John"}

        restored = restore_csv(redacted_csv, key)

        rows = list(csv.reader(io.StringIO(restored)))
        header, data_row = rows[0], rows[1]
        assert len(data_row) == len(header) == 2, (
            f"expected 2 columns per row (structure preserved), got "
            f"header={header} data_row={data_row}"
        )
        assert data_row == ["Smith, John", "Boston"]

    def test_should_roundtrip_plain_csv_with_no_comma_values(self):
        """Control: a plain CSV with no comma-containing values round-trips cleanly.

        Compares parsed rows, not raw text — csv.writer normalizes the line
        terminator to "\\r\\n" regardless of the input's own convention, which
        is orthogonal to the comma-splitting defect this task fixes.
        """
        csv_text = "name,phone\n张三,13812345678\n李四,15900001234"
        redacted, key = redact_csv(csv_text, mode="fast", salt=42)
        restored = restore_csv(redacted, key)

        assert list(csv.reader(io.StringIO(restored))) == list(csv.reader(io.StringIO(csv_text)))

    def test_should_roundtrip_csv_with_preexisting_quoted_comma_field(self):
        """Control: a quoted field with an embedded comma but no PII round-trips
        unchanged — redact_csv/restore_csv must not disturb existing CSV quoting."""
        csv_text = 'name,note\n张三,"hello, world"\n李四,13812345678'
        redacted, key = redact_csv(csv_text, mode="fast", salt=42)
        restored = restore_csv(redacted, key)

        rows = list(csv.reader(io.StringIO(restored)))
        assert rows[1] == ["张三", "hello, world"]
        assert rows[2] == ["李四", "13812345678"]
