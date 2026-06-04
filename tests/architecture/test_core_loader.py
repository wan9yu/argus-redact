"""v0.6.10: single-source loader for the optional Rust _core extension."""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_core_loader_exports_has_core_and_underscore_core():
    from argus_redact._core_loader import HAS_CORE, _core
    assert isinstance(HAS_CORE, bool)
    if HAS_CORE:
        assert _core is not None
    else:
        assert _core is None


def test_no_module_level_core_import_in_consumers():
    """Each consumer must go through _core_loader, not its own try-import.

    Module-level try-blocks like:
        try:
            from argus_redact._core import ...
        except ImportError:
            ...
    are gone. Lazy try-imports inside function bodies (e.g., restore.py:193
    inside def restore()) are still allowed.
    """
    consumers = [
        "src/argus_redact/pure/patterns.py",
        "src/argus_redact/pure/merger.py",
        "src/argus_redact/pure/pseudonym.py",
        "src/argus_redact/glue/redact.py",
    ]
    for rel in consumers:
        src = (REPO_ROOT / rel).read_text()
        assert "\ntry:\n    from argus_redact._core" not in src, (
            f"{rel} still has its own module-level _core try-import; should "
            f"use _core_loader"
        )
