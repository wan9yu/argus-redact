"""Pseudonym code generation with seed support."""

from __future__ import annotations

# Re-exported: stateful pseudonym code generator (Rust core). _core is mandatory
# for Layer-1 (since v0.7.1), so the former Python fallback class is gone.
from argus_redact._core import PseudonymGenerator  # noqa: F401


def max_pseudonym_length(config: dict | None = None) -> int:
    """Return the maximum possible pseudonym length based on config.

    Default format: PREFIX-NNNNN (prefix + dash + 5 digits).
    Useful for streaming buffer sizing.
    """
    from argus_redact.pure.replacer import DEFAULT_PREFIXES

    prefixes = set(DEFAULT_PREFIXES.values())
    if config:
        for type_config in config.values():
            if isinstance(type_config, dict) and "prefix" in type_config:
                prefixes.add(type_config["prefix"])
    if not prefixes:
        return 7  # "P-00000"
    longest_prefix = max(len(p) for p in prefixes)
    return longest_prefix + 1 + 5  # prefix + "-" + 5 digits
