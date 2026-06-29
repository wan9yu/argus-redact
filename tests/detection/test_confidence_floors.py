"""Confidence-floor invariant tests for NER adapters and semantic model profiles.

Guards against drift where an adapter's default confidence drops below a NER
min-confidence floor — that language's L2 NER output is silently filtered to
zero, leaving bare names/locations detectable only via L1 pattern matching.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

from argus_redact.glue.redact import _LANG_NER_ADAPTERS

# Shipped NER adapter module paths — derived from the glue/redact.py SSOT so a
# newly-added adapter is automatically covered without a second hand-edit here.
_ADAPTER_MOD_PATHS = list(_LANG_NER_ADAPTERS.values())


class TestNERAdapterConfidenceFloors:
    @pytest.mark.parametrize("mod_path", _ADAPTER_MOD_PATHS)
    def test_adapter_default_confidence_above_ner_filter_floor(self, mod_path):
        """Adapter _DEFAULT_CONFIDENCE >= _DEFAULT_NER_CONFIDENCE (the default filter floor).

        If an adapter assigns a default confidence that is below the most
        restrictive NER filter threshold (the default-density floor), every
        entity it produces is silently dropped by detect_ner(), and that
        language's L2 layer contributes nothing — bare names/locations leak
        via L1-only detection.
        """
        from argus_redact.pure.hints import _DEFAULT_NER_CONFIDENCE

        mod = importlib.import_module(mod_path)
        adapter_conf = mod._DEFAULT_CONFIDENCE
        assert adapter_conf >= _DEFAULT_NER_CONFIDENCE, (
            f"{mod_path}: _DEFAULT_CONFIDENCE={adapter_conf} < "
            f"_DEFAULT_NER_CONFIDENCE={_DEFAULT_NER_CONFIDENCE} — "
            f"NER output will be entirely filtered on default-density text"
        )

    def test_ner_min_confidence_floors_are_monotone(self):
        """NER density-based min-confidence floors are monotone: high <= medium <= default.

        get_ner_min_confidence returns progressively tighter thresholds as PII
        density decreases.  If this monotone ordering breaks (e.g. medium drift
        above default), the evidence gating inverts.
        """
        from argus_redact._types import Hint
        from argus_redact.pure.hints import _DEFAULT_NER_CONFIDENCE, get_ner_min_confidence

        high_hints = [Hint(type="pii_density", data={"level": "high", "count": 5})]
        medium_hints = [Hint(type="pii_density", data={"level": "medium", "count": 2})]
        no_hints: list = []

        floor_high = get_ner_min_confidence(high_hints)
        floor_medium = get_ner_min_confidence(medium_hints)
        floor_default = get_ner_min_confidence(no_hints)

        assert floor_high <= floor_medium <= floor_default, (
            f"NER floors not monotone: high={floor_high} medium={floor_medium} "
            f"default={floor_default}"
        )
        # The no-hint (default) floor must equal the module constant (not a stale copy).
        assert floor_default == _DEFAULT_NER_CONFIDENCE, (
            f"get_ner_min_confidence(no hints) returned {floor_default}, "
            f"expected _DEFAULT_NER_CONFIDENCE={_DEFAULT_NER_CONFIDENCE}"
        )


class TestSemanticModelProfileFloors:
    def test_all_profiles_confidence_above_detect_semantic_default(self):
        """Each ModelProfile.confidence >= detect_semantic's default min_confidence.

        A profile whose confidence is below the detect_semantic filter floor
        silently drops every semantic detection it makes, rendering the L3 layer
        a no-op for that model.
        """
        from argus_redact.impure.model_profiles import _DEFAULT_PROFILE, PROFILES
        from argus_redact.impure.semantic import detect_semantic

        sig = inspect.signature(detect_semantic)
        detect_default_min = sig.parameters["min_confidence"].default

        all_profiles = {**PROFILES, "_default": _DEFAULT_PROFILE}
        for name, profile in all_profiles.items():
            assert profile.confidence >= detect_default_min, (
                f"Profile '{name}': confidence={profile.confidence} < "
                f"detect_semantic default min_confidence={detect_default_min} — "
                f"all semantic detections would be filtered"
            )
