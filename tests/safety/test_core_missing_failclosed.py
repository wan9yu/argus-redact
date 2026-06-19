"""If the compiled _core extension is missing, redact() must FAIL CLOSED (raise),
never silently return the input unredacted (which would leak PII)."""
import pytest


def test_redact_raises_when_core_missing(monkeypatch):
    import argus_redact._core_loader as loader

    monkeypatch.setattr(loader, "HAS_CORE", False)
    monkeypatch.setattr(loader, "_core", None)

    from argus_redact import redact

    with pytest.raises((ImportError, RuntimeError)):
        redact("call me at 13800138000", lang="zh", mode="fast", salt=42)
