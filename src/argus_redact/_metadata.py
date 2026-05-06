"""Compliance metadata projections from the PII type registry.

Three top-level dicts re-exported from ``argus_redact``:

- ``PIPL_REFERENCES``        : per-type tuple of PIPL article strings
- ``GDPR_SPECIAL_CATEGORIES``: per-type GDPR Article 9 special-category flag
- ``HIPAA_PHI_CATEGORIES``   : per-type HIPAA Safe Harbor identifier category
                              (or ``None`` when the type is not a Safe Harbor identifier)

Keys are the canonical ``PIITypeDef.name`` (e.g. ``"phone"``, ``"id_number"``,
``"medical"``). When the same name appears across multiple language variants
(``zh`` ``phone`` AND ``en`` ``phone``, etc.), variants are merged:

- ``PIPL_REFERENCES``: union of articles across lang variants, preserving order
- ``GDPR_SPECIAL_CATEGORIES``: ``True`` if ANY lang variant marks it special
- ``HIPAA_PHI_CATEGORIES``: first non-``None`` value wins (registry order is
  ``zh`` → ``en`` → ``shared``; deterministic for a given argus-redact version)

Snapshot of the registry at module import. Stable for the lifetime of the
process. Adding a custom type with ``register()`` after import does NOT update
these dicts — by design (matches existing ``pii-types.md`` generation pattern).
"""

from __future__ import annotations

from .specs import list_types


def _build() -> tuple[
    dict[str, tuple[str, ...]],
    dict[str, bool],
    dict[str, str | None],
]:
    pipl: dict[str, tuple[str, ...]] = {}
    gdpr: dict[str, bool] = {}
    hipaa: dict[str, str | None] = {}
    for td in list_types():
        merged = dict.fromkeys(pipl.get(td.name, ()))
        for art in td.pipl_articles:
            merged[art] = None
        pipl[td.name] = tuple(merged)
        gdpr[td.name] = gdpr.get(td.name, False) or bool(td.gdpr_special_category)
        if hipaa.get(td.name) is None:
            hipaa[td.name] = td.hipaa_phi_category
    return pipl, gdpr, hipaa


PIPL_REFERENCES, GDPR_SPECIAL_CATEGORIES, HIPAA_PHI_CATEGORIES = _build()
