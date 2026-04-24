"""PII type specifications — single source of truth for all PII types.

Each PIITypeDef fully describes a PII type: structure, validation, context,
replacement strategy, and evidence. All downstream components (patterns,
generators, fixtures, docs) should derive from these definitions.
"""

from __future__ import annotations

from .registry import PIITypeDef, get, list_types, lookup

# Auto-register all language specs on import
import importlib as _importlib

for _mod in ("zh", "shared"):
    try:
        _importlib.import_module(f"argus_redact.specs.{_mod}")
    except ImportError:
        pass

__all__ = ["PIITypeDef", "get", "list_types", "lookup"]
