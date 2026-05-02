"""Architecture: argus_redact.layers is the single source of truth for layer naming.

Downstream consumers (Gateway concepts, Whitepaper, Landing) import from this
module rather than coining their own L1/L1b/L2/L3 terminology — eliminates drift.
"""

from __future__ import annotations

from argus_redact._types import PatternMatch


class TestLayerConstants:
    def test_layer_constants_are_integers(self):
        from argus_redact.layers import LAYER_NER, LAYER_REGEX, LAYER_SEMANTIC

        assert LAYER_REGEX == 1
        assert LAYER_NER == 2
        assert LAYER_SEMANTIC == 3

    def test_layer_regex_evidence_is_string_sentinel(self):
        # L1b is a sub-stage of L1, not a separate layer index. PatternMatch.layer
        # field is int-typed; L1b candidates flow through as layer=1.
        from argus_redact.layers import LAYER_REGEX_EVIDENCE

        assert LAYER_REGEX_EVIDENCE == "1b"


class TestLayerNames:
    def test_layer_names_covers_all_layers(self):
        from argus_redact.layers import LAYER_NAMES

        assert set(LAYER_NAMES) == {1, 2, 3, "1b"}

    def test_layer_names_descriptions_prefixed(self):
        from argus_redact.layers import LAYER_NAMES

        assert LAYER_NAMES[1].startswith("L1:")
        assert LAYER_NAMES["1b"].startswith("L1b:")
        assert LAYER_NAMES[2].startswith("L2:")
        assert LAYER_NAMES[3].startswith("L3:")


class TestModuleExposure:
    def test_layers_top_level_attribute(self):
        # `import argus_redact; argus_redact.layers.LAYER_REGEX` must work.
        import argus_redact

        assert hasattr(argus_redact, "layers")
        assert argus_redact.layers.LAYER_REGEX == 1

    def test_layers_in_dunder_all(self):
        import argus_redact

        assert "layers" in argus_redact.__all__


class TestPatternMatchIntegration:
    def test_pattern_match_layer_field_accepts_layer_constants(self):
        # Constructing a PatternMatch with our layer constants must work —
        # they are int-typed on purpose so existing layer=1/2/3 callers
        # do not break.
        from argus_redact.layers import LAYER_NER, LAYER_REGEX, LAYER_SEMANTIC

        for lyr in (LAYER_REGEX, LAYER_NER, LAYER_SEMANTIC):
            m = PatternMatch(text="x", type="phone", start=0, end=1, layer=lyr)
            assert m.layer == lyr
