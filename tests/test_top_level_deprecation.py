"""v0.6.10: top-level argus_redact.StreamingRedactor emits DeprecationWarning.

Canonical home is argus_redact.compose.StreamingRedactor (since v0.6.7).
Top-level symbol still resolves (lazy import); removal deferred to v1.0.
"""
import warnings


def test_top_level_streaming_redactor_emits_deprecation():
    import argus_redact
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        _ = argus_redact.StreamingRedactor
        depr = [wi for wi in w if issubclass(wi.category, DeprecationWarning)]
        assert depr, "DeprecationWarning must fire on argus_redact.StreamingRedactor access"
        assert any("compose" in str(wi.message) for wi in depr), (
            "warning must point caller at argus_redact.compose path"
        )


def test_top_level_streaming_redactor_still_resolves():
    """Lazy resolution: the symbol still imports successfully (no v1.0 removal yet)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import argus_redact
        cls = argus_redact.StreamingRedactor
        from argus_redact.compose import StreamingRedactor as canonical
        assert cls is canonical, "top-level must resolve to compose.StreamingRedactor"


def test_compose_streaming_redactor_silent():
    """argus_redact.compose path emits no warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        from argus_redact.compose import StreamingRedactor  # noqa
        assert not any(issubclass(wi.category, DeprecationWarning) for wi in w)


def test_unknown_top_level_attribute_raises_attributeerror():
    """__getattr__ must still raise AttributeError for genuinely unknown names."""
    import argus_redact
    import pytest
    with pytest.raises(AttributeError, match="no attribute"):
        argus_redact.this_does_not_exist  # noqa
