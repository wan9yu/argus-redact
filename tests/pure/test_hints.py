"""Tests for cross-layer hints protocol."""

from argus_redact._types import Hint, PatternMatch


class TestHintDataclass:
    def test_should_create_hint_with_required_fields(self):
        hint = Hint(type="self_reference_tier", data={"tier": 1})

        assert hint.type == "self_reference_tier"
        assert hint.data == {"tier": 1}

    def test_should_have_defaults(self):
        hint = Hint(type="test")

        assert hint.data == {}
        assert hint.region == (0, 0)
        assert hint.source_layer == 1

    def test_should_be_frozen(self):
        hint = Hint(type="test")
        try:
            hint.type = "other"
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestProduceHints:
    """L1a produces hints from detected entities."""

    def test_should_produce_tier1_when_self_ref_with_pii(self):
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="我", type="self_reference", start=0, end=1),
            PatternMatch(text="糖尿病", type="medical", start=4, end=7),
        ]

        hints = produce_hints(entities, text="我确诊了糖尿病")

        tier_hints = [h for h in hints if h.type == "self_reference_tier"]
        assert len(tier_hints) == 1
        assert tier_hints[0].data["tier"] == 1

    def test_should_produce_tier2_when_self_ref_without_pii(self):
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="我", type="self_reference", start=0, end=1),
        ]

        hints = produce_hints(entities, text="我觉得天气很好")

        tier_hints = [h for h in hints if h.type == "self_reference_tier"]
        assert len(tier_hints) == 1
        assert tier_hints[0].data["tier"] == 2

    def test_should_produce_tier3_when_command(self):
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="我", type="self_reference", start=0, end=1),
        ]

        hints = produce_hints(entities, text="我想问一下怎么用Python")

        tier_hints = [h for h in hints if h.type == "self_reference_tier"]
        assert len(tier_hints) == 1
        assert tier_hints[0].data["tier"] == 3

    def test_should_produce_text_intent_hint(self):
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="我", type="self_reference", start=0, end=1),
        ]

        hints = produce_hints(entities, text="帮我看看这段代码")

        intent_hints = [h for h in hints if h.type == "text_intent"]
        assert len(intent_hints) == 1
        assert intent_hints[0].data["intent"] == "instruction"

    def test_should_produce_narrative_intent_when_pii(self):
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="我", type="self_reference", start=0, end=1),
            PatternMatch(text="13812345678", type="phone", start=4, end=15),
        ]

        hints = produce_hints(entities, text="我的电话13812345678")

        intent_hints = [h for h in hints if h.type == "text_intent"]
        assert len(intent_hints) == 1
        assert intent_hints[0].data["intent"] == "narrative"

    def test_should_produce_no_self_ref_hint_when_no_self_ref(self):
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="13812345678", type="phone", start=2, end=13),
        ]

        hints = produce_hints(entities, text="电话13812345678")

        tier_hints = [h for h in hints if h.type == "self_reference_tier"]
        assert len(tier_hints) == 0

    def test_should_produce_kinship_always_tier1(self):
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="我妈", type="self_reference", start=0, end=2),
        ]

        hints = produce_hints(entities, text="我妈最近身体不好")

        tier_hints = [h for h in hints if h.type == "self_reference_tier"]
        assert tier_hints[0].data["tier"] == 1


class TestConsumeHints:
    """Consumers read hints to adjust their behavior."""

    def test_person_threshold_should_increase_when_instruction(self):
        from argus_redact.pure.hints import get_person_threshold

        hints = [Hint(type="text_intent", data={"intent": "instruction"})]

        threshold = get_person_threshold(hints)

        assert threshold > 0.8, "Instruction text should raise person name threshold"

    def test_person_threshold_should_decrease_when_pii_context(self):
        from argus_redact.pure.hints import get_person_threshold

        hints = [Hint(type="text_intent", data={"intent": "narrative"})]

        threshold = get_person_threshold(hints)

        assert threshold <= 0.8

    def test_person_threshold_default_when_no_hints(self):
        from argus_redact.pure.hints import get_person_threshold

        threshold = get_person_threshold([])

        assert threshold == 0.8

    def test_should_filter_self_ref_entities_by_tier(self):
        from argus_redact.pure.hints import filter_self_reference

        entities = [
            PatternMatch(text="我", type="self_reference", start=0, end=1),
            PatternMatch(text="糖尿病", type="medical", start=4, end=7),
        ]
        hints = [Hint(type="self_reference_tier", data={"tier": 1})]

        result = filter_self_reference(entities, hints)

        assert any(e.type == "self_reference" for e in result), "Tier 1: keep"

    def test_should_drop_self_ref_when_tier2(self):
        from argus_redact.pure.hints import filter_self_reference

        entities = [
            PatternMatch(text="我", type="self_reference", start=0, end=1),
        ]
        hints = [Hint(type="self_reference_tier", data={"tier": 2})]

        result = filter_self_reference(entities, hints)

        assert not any(e.type == "self_reference" for e in result), "Tier 2: drop"

    def test_should_drop_self_ref_when_tier3(self):
        from argus_redact.pure.hints import filter_self_reference

        entities = [
            PatternMatch(text="我", type="self_reference", start=0, end=1),
        ]
        hints = [Hint(type="self_reference_tier", data={"tier": 3})]

        result = filter_self_reference(entities, hints)

        assert not any(e.type == "self_reference" for e in result), "Tier 3: drop"


class TestPiiDensityHint:
    """L1a should emit pii_density hint based on entity count."""

    def test_should_produce_high_density_when_multiple_pii(self):
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="13812345678", type="phone", start=2, end=13),
            PatternMatch(text="110101199003074610", type="id_number", start=18, end=36),
            PatternMatch(text="test@example.com", type="email", start=40, end=56),
        ]

        hints = produce_hints(entities, text="电话13812345678，身份证110101199003074610，邮箱test@example.com")

        density = [h for h in hints if h.type == "pii_density"]
        assert len(density) == 1
        assert density[0].data["level"] == "high"
        assert density[0].data["count"] == 3

    def test_should_produce_low_density_when_no_pii(self):
        from argus_redact.pure.hints import produce_hints

        hints = produce_hints([], text="今天天气不错")

        density = [h for h in hints if h.type == "pii_density"]
        assert len(density) == 1
        assert density[0].data["level"] == "none"
        assert density[0].data["count"] == 0

    def test_should_produce_medium_density_when_one_pii(self):
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="13812345678", type="phone", start=2, end=13),
        ]

        hints = produce_hints(entities, text="电话13812345678")

        density = [h for h in hints if h.type == "pii_density"]
        assert density[0].data["level"] == "medium"

    def test_should_not_count_self_reference_as_pii(self):
        from argus_redact.pure.hints import produce_hints

        entities = [
            PatternMatch(text="我", type="self_reference", start=0, end=1),
        ]

        hints = produce_hints(entities, text="我觉得天气很好")

        density = [h for h in hints if h.type == "pii_density"]
        assert density[0].data["count"] == 0


class TestNerHintConsumers:
    """L2 NER should consume hints to adjust behavior."""

    def test_should_skip_ner_when_instruction(self):
        from argus_redact.pure.hints import should_skip_ner

        hints = [Hint(type="text_intent", data={"intent": "instruction"})]

        assert should_skip_ner(hints) is True

    def test_should_not_skip_ner_when_narrative(self):
        from argus_redact.pure.hints import should_skip_ner

        hints = [Hint(type="text_intent", data={"intent": "narrative"})]

        assert should_skip_ner(hints) is False

    def test_should_not_skip_ner_when_no_hints(self):
        from argus_redact.pure.hints import should_skip_ner

        assert should_skip_ner([]) is False

    def test_should_lower_confidence_when_high_density(self):
        from argus_redact.pure.hints import get_ner_min_confidence

        hints = [Hint(type="pii_density", data={"level": "high", "count": 3})]

        conf = get_ner_min_confidence(hints)

        assert conf < 0.5, "High PII density should lower NER threshold"

    def test_should_raise_confidence_when_no_density(self):
        from argus_redact.pure.hints import get_ner_min_confidence

        hints = [Hint(type="pii_density", data={"level": "none", "count": 0})]

        conf = get_ner_min_confidence(hints)

        assert conf >= 0.5

    def test_should_default_confidence_when_no_hints(self):
        from argus_redact.pure.hints import get_ner_min_confidence

        conf = get_ner_min_confidence([])

        assert conf == 0.5

    def test_should_not_skip_ner_when_instruction_but_has_pii(self):
        """Even instruction text should run NER if L1 found PII."""
        from argus_redact.pure.hints import should_skip_ner

        hints = [
            Hint(type="text_intent", data={"intent": "instruction"}),
            Hint(type="pii_density", data={"level": "medium", "count": 1}),
        ]

        assert should_skip_ner(hints) is False
