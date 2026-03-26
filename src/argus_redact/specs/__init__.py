"""PII type specifications — single source of truth for all PII types.

Each PIITypeDef fully describes a PII type: structure, validation, context,
replacement strategy, and evidence. All downstream components (patterns,
generators, fixtures, docs) should derive from these definitions.
"""

from __future__ import annotations

from .registry import PIITypeDef, get, list_types, lookup

__all__ = ["PIITypeDef", "get", "list_types", "lookup"]
