"""Drift guard: every type in shared.ron has a registry PIITypeDef.

``crates/argus-redact-core/data/shared.ron`` is the cross-language detection SSOT
loaded unconditionally at runtime — every pattern there IS detected and redacted.
A type present in ``shared.ron`` but ABSENT from the Python registry gets no
``PIITypeDef``: ``redact(..., report=True)`` reports it at a bare default
sensitivity and ``compliance_for`` returns ``None`` (no statute mapping). This
guards against a future ``shared.ron`` type shipping without a registration.

Membership is checked at the NAME level (not ``(lang, name)``): a ``shared.ron``
type may be registered under a specific language pack (e.g. ``age`` under ``zh``),
which still satisfies the "has a ``PIITypeDef``" requirement.
"""

from __future__ import annotations

import re
from pathlib import Path

import argus_redact.specs  # noqa: F401  — importing the package registers every spec
from argus_redact.specs.registry import lookup

_SHARED_RON = (
    Path(__file__).resolve().parents[2] / "crates" / "argus-redact-core" / "data" / "shared.ron"
)

_TYPE_RE = re.compile(r'type_:\s*"([^"]+)"')


def _shared_ron_type_names() -> set[str]:
    names = set(_TYPE_RE.findall(_SHARED_RON.read_text(encoding="utf-8")))
    assert names, "no type_ entries parsed from shared.ron — parser or path is wrong"
    return names


def test_every_shared_ron_type_has_a_registry_row():
    """Each distinct type name in shared.ron resolves to at least one PIITypeDef."""
    missing = sorted(name for name in _shared_ron_type_names() if not lookup(name))
    assert not missing, (
        f"shared.ron types with no registry PIITypeDef: {missing}. "
        "Register each in src/argus_redact/specs/ — a shared.ron type is detected "
        "and redacted at runtime but reports a bare sensitivity and no compliance "
        "classification until it has a PIITypeDef."
    )
