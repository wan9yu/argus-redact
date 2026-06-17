"""Single-source loader for the Rust _core extension.

``_core`` is REQUIRED for Layer-1 — it has been mandatory since v0.7.1, when
``lang/_loader`` began raising ``ImportError`` (and all pattern data started
flowing exclusively from ``_core.builtin_patterns``). The try/except below sets
``HAS_CORE`` so ``lang/_loader.core_patterns`` can raise that explicit
mandatory-``_core`` ``ImportError`` (rather than an opaque attribute error)
when the extension is missing; the no-core code path is never exercised in a
working install.

Prior to v0.6.10, each consumer (pure/patterns, pure/merger, pure/pseudonym,
glue/redact) carried its own module-level ``try: from argus_redact import _core``
block. This module consolidates them. Consumers do:

    from argus_redact._core_loader import _core, HAS_CORE

Class-level / function-level imports (PseudonymGenerator, match_patterns, etc.)
stay in the consumer's namespace, but they now derive from the loader's _core
reference instead of duplicating the try/except themselves.
"""

try:
    from argus_redact import _core  # type: ignore[attr-defined]
    HAS_CORE = True
except ImportError:
    _core = None  # type: ignore[assignment]
    HAS_CORE = False
