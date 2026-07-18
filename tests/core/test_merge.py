"""Tests for entity merger — dedup overlapping spans from multiple layers."""

from unittest.mock import MagicMock, patch

from argus_redact import redact
from argus_redact._types import NEREntity, PatternMatch
from argus_redact.impure.ner import NERAdapter
from argus_redact.pure.merger import merge_entities


def _m(text, type, start, end=None, confidence=1.0, layer=0):
    if end is None:
        end = start + len(text)
    return PatternMatch(
        text=text, type=type, start=start, end=end, confidence=confidence, layer=layer
    )


class TestMergeNoOverlap:
    """Non-overlapping entities should all be kept."""

    def test_should_keep_all_when_no_overlap(self):
        entities = [
            _m("张三", "person", 0),
            _m("13812345678", "phone", 5),
        ]

        result = merge_entities(entities)

        assert len(result) == 2

    def test_should_return_sorted_by_position(self):
        entities = [
            _m("13812345678", "phone", 10),
            _m("张三", "person", 0),
        ]

        result = merge_entities(entities)

        assert result[0].start < result[1].start

    def test_should_return_empty_when_empty_input(self):
        result = merge_entities([])

        assert result == []

    def test_should_return_single_when_one_entity(self):
        entities = [_m("张三", "person", 0)]

        result = merge_entities(entities)

        assert len(result) == 1


class TestMergeExactOverlap:
    """Same span detected by multiple layers."""

    def test_should_keep_higher_confidence_when_exact_overlap(self):
        entities = [
            _m("张三", "person", 0, 2, confidence=1.0),
            _m("张三", "person", 0, 2, confidence=0.85),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].confidence == 1.0

    def test_should_keep_higher_confidence_when_ner_wins(self):
        entities = [
            _m("张三", "person", 0, 2, confidence=0.5),
            _m("张三", "person", 0, 2, confidence=0.95),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_should_dedup_when_identical(self):
        entities = [
            _m("张三", "person", 0, 2, confidence=0.9),
            _m("张三", "person", 0, 2, confidence=0.9),
        ]

        result = merge_entities(entities)

        assert len(result) == 1


class TestMergeContainment:
    """Entity A contains entity B — keep only A."""

    def test_should_keep_longer_when_one_contains_other(self):
        entities = [
            _m("三里屯的星巴克", "location", 0, 7, confidence=0.8),
            _m("星巴克", "organization", 4, 7, confidence=0.9),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].text == "三里屯的星巴克"

    def test_should_keep_longer_when_inner_has_higher_confidence(self):
        entities = [
            _m("北京市朝阳区", "location", 0, 6, confidence=0.7),
            _m("朝阳区", "location", 3, 6, confidence=0.95),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].text == "北京市朝阳区"


class TestMergePartialOverlap:
    """Partially overlapping spans — keep the longer one."""

    def test_should_keep_longer_when_partial_overlap(self):
        entities = [
            _m("张三丰", "person", 0, 3, confidence=0.8),
            _m("三丰集团", "organization", 1, 5, confidence=0.7),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].text == "三丰集团"  # longer span

    def test_should_keep_higher_confidence_when_same_length_overlap(self):
        entities = [
            _m("AB", "person", 0, 2, confidence=0.9),
            _m("BC", "person", 1, 3, confidence=0.8),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].text == "AB"


class TestMergeComplexScenarios:
    """Real-world-like combinations."""

    def test_should_handle_regex_and_ner_together(self):
        entities = [
            _m("13812345678", "phone", 6, 17, confidence=1.0),  # regex
            _m("张三", "person", 0, 2, confidence=0.85),  # NER
        ]

        result = merge_entities(entities)

        assert len(result) == 2
        types = {r.type for r in result}
        assert types == {"phone", "person"}

    def test_should_handle_multiple_overlaps_in_sequence(self):
        entities = [
            _m("张三", "person", 0, 2, confidence=0.9),
            _m("张三", "person", 0, 2, confidence=0.85),
            _m("13812345678", "phone", 5, 16, confidence=1.0),
            _m("李四", "person", 20, 22, confidence=0.9),
            _m("李四", "person", 20, 22, confidence=0.8),
        ]

        result = merge_entities(entities)

        assert len(result) == 3
        texts = {r.text for r in result}
        assert texts == {"张三", "13812345678", "李四"}

    def test_should_handle_adjacent_entities(self):
        entities = [
            _m("张三", "person", 0, 2, confidence=0.9),
            _m("李四", "person", 2, 4, confidence=0.9),
        ]

        result = merge_entities(entities)

        assert len(result) == 2

    def test_should_handle_three_way_overlap_chain(self):
        entities = [
            _m("ABC", "person", 0, 3, confidence=0.8),
            _m("BCD", "person", 1, 4, confidence=0.7),
            _m("CDE", "person", 2, 5, confidence=0.9),
        ]

        result = merge_entities(entities)

        assert len(result) == 1

    def test_should_prefer_regex_over_ner_when_same_span(self):
        entities = [
            _m("13812345678", "phone", 0, 11, confidence=1.0),
            _m("13812345678", "phone", 0, 11, confidence=0.85),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].confidence == 1.0

    def test_should_keep_outer_when_lower_confidence_but_longer(self):
        entities = [
            _m("北京市朝阳区", "location", 0, 6, confidence=0.6),
            _m("朝阳", "location", 3, 5, confidence=0.99),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].text == "北京市朝阳区"

    def test_should_handle_different_types_at_same_position(self):
        entities = [
            _m("Apple", "organization", 0, 5, confidence=0.9),
            _m("Apple", "person", 0, 5, confidence=0.7),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].type == "organization"

    def test_should_produce_valid_offsets_when_l1_l2_partial_overlap(self):
        """L1 [3,10) overlaps L2 [5,12) → merged span must be valid."""
        text = "住在三里屯的星巴克咖啡厅"
        entities = [
            _m("三里屯的星巴克", "address", 2, 9),  # L1
            _m("星巴克咖啡厅", "organization", 6, 12),  # L2 overlaps
        ]

        result = merge_entities(entities, text=text)

        # Merged: should pick one or both, but offsets must be valid
        for e in result:
            assert e.start >= 0
            assert e.end <= len(text)
            assert text[e.start : e.end] == e.text, (
                f"Offset mismatch: text[{e.start}:{e.end}]='{text[e.start : e.end]}' != '{e.text}'"
            )


class TestMergeSelfReferencePriority:
    """self_reference should split overlapping entities, not be swallowed."""

    def test_should_preserve_wo_when_overlaps_with_longer_entity(self):
        # "我在协和医院" — "我" is self_reference, "我在协和医院" is org/address
        text = "我在协和医院做了体检"
        entities = [
            _m("我", "self_reference", 0, 1),
            _m("我在协和医院", "organization", 0, 6),
        ]

        result = merge_entities(entities, text=text)
        types = {r.type for r in result}

        assert "self_reference" in types, "我 should not be swallowed by org"

    def test_should_trim_other_entity_when_wo_splits_it(self):
        text = "我在协和医院做了体检"
        entities = [
            _m("我", "self_reference", 0, 1),
            _m("我在协和医院", "organization", 0, 6),
        ]

        result = merge_entities(entities, text=text)

        # Should have self_reference "我" + trimmed org
        assert any(r.type == "self_reference" and r.text == "我" for r in result)
        trimmed = [r for r in result if r.type == "organization"]
        if trimmed:
            assert trimmed[0].start >= 1, "org should be trimmed to after 我"

    def test_should_keep_both_when_wo_at_start_of_address(self):
        text = "我家在北京市朝阳区"
        entities = [
            _m("我", "self_reference", 0, 1),
            _m("我家在北京", "address", 0, 5),
        ]

        result = merge_entities(entities, text=text)
        types = {r.type for r in result}

        assert "self_reference" in types

    def test_should_keep_both_when_wo_mama_overlaps_with_person(self):
        text = "我妈张三去了医院"
        entities = [
            _m("我妈", "self_reference", 0, 2),
            _m("我妈张三", "person", 0, 4),
        ]

        result = merge_entities(entities, text=text)
        types = {r.type for r in result}

        assert "self_reference" in types

    def test_should_not_affect_non_self_reference_overlap(self):
        # Normal overlap behavior unchanged
        entities = [
            _m("北京", "location", 0, 2),
            _m("北京市朝阳区", "address", 0, 6),
        ]

        result = merge_entities(entities)

        assert len(result) == 1
        assert result[0].text == "北京市朝阳区"


def test_priority_trim_drops_u001c_only_remainder():
    # Python str.strip() drops a U+001C-only trimmed remainder; the Rust merge path
    # (now the production engine) must match via py_strip parity. self_reference
    # [0,1] splits `other` [0,3]; trimming `other` to start at 1 leaves "\x1c\x1c"
    # → dropped, so only the self_reference span survives.
    out = merge_entities(
        [
            _m("我", "self_reference", 0, 1),
            _m("我\x1c\x1c", "other", 0, 3),
        ],
        text="我\x1c\x1c",
    )
    assert [(e.text, e.type, e.start, e.end) for e in out] == [("我", "self_reference", 0, 1)]


class TestSelfReferenceContainerHeadGuard:
    """An interior self_reference must not drop the head of its container entity."""

    def test_should_keep_container_whole_when_interior_sr_overruns_tail(self):
        # person "公司我"[0,3] + self_reference "我们"[2,4]: the sr starts interior
        # (2>0) and overruns the tail (4>3). The container must win WHOLE —
        # replacing it with the sr drops the head "公司" and, once the sr is
        # tier-filtered, leaks the entire name the caller asked to redact.
        text = "公司我们裁员了"
        entities = [
            _m("公司我", "person", 0, 3),
            _m("我们", "self_reference", 2, 4),
        ]

        result = merge_entities(entities, text)

        assert [(e.text, e.type, e.start, e.end) for e in result] == [("公司我", "person", 0, 3)]


class TestPersonCrossLayerMerge:
    """A person span on one detection layer overlapping a person span on another
    prefers the higher layer (NER over an over-greedy L1 regex candidate), with
    the loser's non-overlapping tail trimmed and kept — not silently dropped.
    Scoped to person-vs-person across DIFFERENT layers only; see the SAME-layer
    control below for the boundary.
    """

    def test_should_trim_remainder_when_l1_l2_partial_overlap(self):
        # L1 person "李明明王"[2,6] (fused, wrong) overlaps L2 person "李明明"[2,5]
        # (correct, starts at the same place). L2 wins the overlap; the L1
        # loser's tail "王"[5,6] survives as its own person remainder instead
        # of being dropped into the clear.
        text = "客户李明明王联系电话13800138000"
        entities = [
            _m("李明明王", "person", 2, 6, layer=1),
            _m("李明明", "person", 2, 5, layer=2),
        ]

        result = merge_entities(entities, text)

        assert [(e.text, e.type, e.start, e.end, e.layer) for e in result] == [
            ("李明明", "person", 2, 5, 2),
            ("王", "person", 5, 6, 1),
        ]

    def test_should_fully_cover_fused_name_with_two_l2_spans(self):
        # L1 person "李明明王小丽"[2,8] fuses two real names into one candidate.
        # Two L2 spans cover each name exactly; together they must claim the
        # whole range so no trailing character of the second name survives
        # unredacted.
        text = "客户李明明王小丽联系电话13800138000"
        entities = [
            _m("李明明王小丽", "person", 2, 8, layer=1),
            _m("李明明", "person", 2, 5, layer=2),
            _m("王小丽", "person", 5, 8, layer=2),
        ]

        result = merge_entities(entities, text)

        assert [(e.text, e.type, e.start, e.end, e.layer) for e in result] == [
            ("李明明", "person", 2, 5, 2),
            ("王小丽", "person", 5, 8, 2),
        ]

    def test_should_use_length_then_confidence_when_same_layer(self):
        # SAME-layer control: the two spans differ only in whether they overlap
        # at the SAME layer. person_cross_layer_winner returns None for equal
        # layers, so this must fall through to the pre-existing length-then-
        # confidence resolution (longer span wins whole, no trim) — proving the
        # rule above is scoped to a CROSS-layer overlap only. This is the
        # non-regression guard for the length/confidence resolver everywhere
        # else in this file.
        text = "客户李明明王联系电话13800138000"
        entities = [
            _m("李明明王", "person", 2, 6, layer=2),
            _m("李明明", "person", 2, 5, layer=2),
        ]

        result = merge_entities(entities, text)

        assert [(e.text, e.type, e.start, e.end, e.layer) for e in result] == [
            ("李明明王", "person", 2, 6, 2),
        ]


class TestKnownIssuesFusedNamePersonRepro:
    """End-to-end repro of the fused-name person leak documented in
    docs/known-issues.md, now closed by the cross-layer merge rule above.

    Pre-fix, the L1 person candidate generator fused two adjacent names into
    one 4-character candidate ("李明明王"), the merge kept that longer L1 span
    outright, both NER spans were discarded, and "小丽" leaked into the
    redacted output. The NER adapter is mocked (per project convention) so
    this runs without a real model — the L1 regex/person layer is real.
    """

    def test_should_redact_both_names_when_l1_fuses_them(self):
        text = "客户李明明王小丽联系电话13800138000"
        adapter = MagicMock(spec=NERAdapter)
        adapter.detect.return_value = [
            NEREntity("李明明", "person", 2, 5, 0.95),
            NEREntity("王小丽", "person", 5, 8, 0.95),
        ]

        with patch("argus_redact.glue.redact._get_ner_adapters", return_value=[adapter]):
            redacted, key = redact(text, salt=42, mode="ner", lang="zh")

        assert "小丽" not in redacted
        assert "李明明" not in redacted
        assert "王小丽" not in redacted
