"""Single-source loader for the optional Rust _core extension.

Prior to v0.6.10, each consumer (pure/patterns, pure/merger, pure/pseudonym,
glue/redact) carried its own module-level ``try: from argus_redact import _core``
block. This module consolidates them. Consumers do:

    from argus_redact._core_loader import _core, HAS_CORE

Class-level / function-level imports (PseudonymGenerator, match_patterns, etc.)
stay in the consumer's namespace, but they now derive from the loader's _core
reference instead of duplicating the try/except themselves.

Lazy try-imports inside function bodies (e.g. ``pure/restore.py`` inside the
``restore()`` body) are intentionally kept as-is — they fire only on the hot
path and add no module-level cost.
"""

try:
    from argus_redact import _core  # type: ignore[attr-defined]
    HAS_CORE = True
except ImportError:
    _core = None  # type: ignore[assignment]
    HAS_CORE = False
