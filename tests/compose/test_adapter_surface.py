"""v0.6.11: Layer 2 adapter-author surface — register_pii_type, PIITypeDef, PatternMatch."""
import pytest


def test_adapter_surface_imports():
    from argus_redact.compose import register_pii_type, PIITypeDef, PatternMatch
    assert callable(register_pii_type)
    assert isinstance(PIITypeDef, type)
    assert isinstance(PatternMatch, type)


def test_adapter_surface_in_all():
    import argus_redact.compose as c
    for name in ("register_pii_type", "PIITypeDef", "PatternMatch"):
        assert name in c.__all__, f"compose.__all__ missing {name!r}"


def test_register_pii_type_is_specs_register():
    """compose.register_pii_type IS the underlying specs.registry.register."""
    from argus_redact.compose import register_pii_type
    from argus_redact.specs.registry import register
    assert register_pii_type is register


def test_pii_typedef_is_specs_pii_typedef():
    from argus_redact.compose import PIITypeDef
    from argus_redact.specs.registry import PIITypeDef as SpecsPIITypeDef
    assert PIITypeDef is SpecsPIITypeDef


def test_pattern_match_is_internal_pattern_match():
    from argus_redact.compose import PatternMatch
    from argus_redact._types import PatternMatch as InternalPatternMatch
    assert PatternMatch is InternalPatternMatch


def test_register_custom_type_round_trips():
    """Full round-trip: register custom type, run redact() with _pre_detected, restore."""
    from argus_redact.compose import register_pii_type, PIITypeDef, PatternMatch
    from argus_redact import redact, restore
    from argus_redact.specs.registry import unregister

    register_pii_type(PIITypeDef(
        name="employee_id_test", lang="en",
        format="EMP-NNNNNN",
        strategy="pseudonym",
        sensitivity=2,
    ))
    try:
        text = "call EMP-123456 about Q4"
        redacted, key = redact(
            text, lang="en", salt=b"a" * 32,
            _pre_detected=[
                PatternMatch(type="employee_id_test", text="EMP-123456",
                             start=5, end=15),
            ],
        )
        assert "EMP-123456" not in redacted, "custom-type entity should be redacted"
        assert restore(redacted, key) == text
    finally:
        unregister("en", "employee_id_test")
