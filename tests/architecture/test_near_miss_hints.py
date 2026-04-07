"""Tests for near-miss — format matches but validation fails."""

from argus_redact._types import Hint, PatternMatch


class TestMatchResultNearMiss:
    """match_patterns should collect validate-failed matches as near_misses."""

    def test_should_have_near_misses_for_invalid_checksum_id(self):
        from argus_redact.pure.patterns import match_patterns
        from argus_redact.lang.zh.patterns import PATTERNS
        from argus_redact.lang.shared.patterns import PATTERNS as SHARED

        text = "身份证110101199003071234"
        entities, near_misses = match_patterns(text, PATTERNS + SHARED)

        assert not any(r.type == "id_number" for r in entities)
        assert len(near_misses) >= 1
        assert near_misses[0].type == "id_number"

    def test_should_have_no_near_misses_for_valid_id(self):
        from argus_redact.pure.patterns import match_patterns
        from argus_redact.lang.zh.patterns import PATTERNS
        from argus_redact.lang.shared.patterns import PATTERNS as SHARED

        text = "身份证110101199003074610"
        entities, near_misses = match_patterns(text, PATTERNS + SHARED)

        assert any(r.type == "id_number" for r in entities)
        assert not any(nm.type == "id_number" for nm in near_misses)

    def test_should_have_no_near_misses_for_random_digits(self):
        from argus_redact.pure.patterns import match_patterns
        from argus_redact.lang.zh.patterns import PATTERNS
        from argus_redact.lang.shared.patterns import PATTERNS as SHARED

        text = "编号123456789012345678"
        entities, near_misses = match_patterns(text, PATTERNS + SHARED)

        assert len(near_misses) == 0


class TestNearMissHintFlow:
    """Near misses should flow as hints to produce_hints."""

    def test_should_emit_hint_for_near_miss(self):
        from argus_redact.pure.hints import produce_hints
        from argus_redact.pure.patterns import match_patterns
        from argus_redact.lang.zh.patterns import PATTERNS
        from argus_redact.lang.shared.patterns import PATTERNS as SHARED

        text = "身份证110101199003071234"
        entities, near_misses = match_patterns(text, PATTERNS + SHARED)

        hints = produce_hints(entities, text, near_misses=near_misses)

        near_miss_hints = [h for h in hints if h.type == "near_miss_format"]
        assert len(near_miss_hints) >= 1
        assert near_miss_hints[0].data["original_type"] == "id_number"

    def test_near_miss_should_not_be_redacted(self):
        from argus_redact import redact

        text = "身份证110101199003071234"
        redacted, key = redact(text, seed=42, mode="fast")

        assert "110101199003071234" in redacted
