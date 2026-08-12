"""Shared person-name detection binder over the Rust ``_core`` FFI.

The en and zh ``person.py`` modules are byte-identical marshalling shims: build
the Rust ``PatternMatch`` list for the proximity ``pii_entities``, call the
language's Rust detector, and rebuild Python ``PatternMatch`` objects from the
result. That one conversion loop lives here so the two shims stay in lockstep;
each language module only binds its Rust detector function and its threshold.
"""

from __future__ import annotations

from typing import Callable

from argus_redact._types import PatternMatch, from_rust_pm, to_rust_pm


def detect_person(
    rust_fn: Callable,
    text: str,
    *,
    pii_entities: list[PatternMatch] | None,
    known_names: list[str] | None,
    threshold: float,
) -> list[PatternMatch]:
    """Marshal across the FFI and run ``rust_fn`` (a ``_core.detect_person_names_*``).

    ``rust_fn(text, rust_pii, known_names, threshold)`` — the argument order every
    language detector shares. All ``pii_entities`` fields are forwarded so the Rust
    scorer can read ``type`` (e.g. filter ``self_reference``) as well as spans.
    """
    rust_pii = [to_rust_pm(e) for e in pii_entities] if pii_entities else None
    return [from_rust_pm(r) for r in rust_fn(text, rust_pii, known_names, threshold)]
