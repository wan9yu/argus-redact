"""Layer 2 (compose.*) signature snapshot — best-effort lock (v0.6.11).

Layer 2 SLA: signatures may evolve in minor releases with deprecation cycles.
This snapshot fires when any compose.* signature changes; the change is
allowed but must be deliberate — update the snapshot AND note the evolution
in CHANGELOG under the next release's notes.

Contrast with tests/architecture/test_frozen_api.py: Layer 1 drift requires
a major-version bump (v2.0). Layer 2 drift just requires a CHANGELOG entry.

To regenerate after an intentional Layer 2 evolution:

    python -c "
    import inspect, dataclasses
    import argus_redact.compose as c
    from argus_redact import RedactReport
    fns = ['prompt_anchor', 'expand_aliases', 'register_pii_type']
    for n in fns:
        print(repr(n), ':', repr(str(inspect.signature(getattr(c, n)))) + ',')
    print('PIITypeDef:', sorted(f.name for f in dataclasses.fields(c.PIITypeDef)))
    print('PatternMatch:', sorted(f.name for f in dataclasses.fields(c.PatternMatch)))
    print('RedactReport:', sorted(f.name for f in dataclasses.fields(RedactReport)))
    "

``RedactReport`` is imported from top-level ``argus_redact``, not ``c`` — it
is a Layer 1 type (see ``tests/architecture/test_frozen_api.py``) that has
never been re-exported through ``argus_redact.compose``; its field-set is
pinned in this Layer-2 file only because it is consumed by the same
best-effort-evolution SLA as ``PIITypeDef``/``PatternMatch``, not because it
lives in ``compose``.
"""

import dataclasses
import inspect

import pytest

import argus_redact.compose as c
from argus_redact import RedactReport

COMPOSE_SIGNATURES = {
    "prompt_anchor": "(key: 'dict', lang: 'str' = 'zh', *, anchor: 'Anchor | None' = None) -> 'str'",  # noqa: E501
    "expand_aliases": "(key: 'dict', lang: 'str | None' = None) -> 'dict'",
    "register_pii_type": "(typedef: 'PIITypeDef') -> 'PIITypeDef'",
}

PIITYPEDEF_FIELDS = frozenset(
    {
        "_patterns",
        "charset",
        "checksum",
        "counterexamples",
        "description",
        "examples",
        "faker_reserved",
        "format",
        "gdpr_special_category",
        "hipaa_phi_category",
        "label",
        "lang",
        "length",
        "mask_rule",
        "name",
        "pipl_articles",
        "prefixes",
        "sensitivity",
        "separators",
        "source",
        "strategy",
        "structure",
        "suffixes",
        "validate",
    }
)

PATTERNMATCH_FIELDS = frozenset(
    {
        "confidence",
        "end",
        "layer",
        "start",
        "text",
        "type",
    }
)

REDACTREPORT_FIELDS = frozenset(
    {
        "redacted_text",
        "key",
        "entities",
        "stats",
        "risk",
        "residual_personal_data",
        "security_events",
        "coverage",
        "layers_used",
    }
)


@pytest.mark.parametrize("name,expected", list(COMPOSE_SIGNATURES.items()))
def test_compose_signature_snapshot(name, expected):
    fn = getattr(c, name)
    actual = str(inspect.signature(fn))
    assert actual == expected, (
        f"compose.{name} signature changed.\n"
        f"  expected: {expected}\n"
        f"  actual:   {actual}\n"
        f"If intentional: update COMPOSE_SIGNATURES and add a 'Layer 2 "
        f"evolution' note to the next release's CHANGELOG entry."
    )


def test_pii_typedef_fields_snapshot():
    actual = frozenset(f.name for f in dataclasses.fields(c.PIITypeDef))
    assert actual == PIITYPEDEF_FIELDS, (
        f"PIITypeDef field set changed.\n"
        f"  expected: {sorted(PIITYPEDEF_FIELDS)}\n"
        f"  actual:   {sorted(actual)}\n"
        f"If intentional: update PIITYPEDEF_FIELDS + CHANGELOG."
    )


def test_pattern_match_fields_snapshot():
    actual = frozenset(f.name for f in dataclasses.fields(c.PatternMatch))
    assert actual == PATTERNMATCH_FIELDS, (
        f"PatternMatch field set changed.\n"
        f"  expected: {sorted(PATTERNMATCH_FIELDS)}\n"
        f"  actual:   {sorted(actual)}\n"
        f"If intentional: update PATTERNMATCH_FIELDS + CHANGELOG."
    )


def test_redact_report_fields_snapshot():
    actual = frozenset(f.name for f in dataclasses.fields(RedactReport))
    assert actual == REDACTREPORT_FIELDS, (
        f"RedactReport field set changed.\n"
        f"  expected: {sorted(REDACTREPORT_FIELDS)}\n"
        f"  actual:   {sorted(actual)}\n"
        f"If intentional: update REDACTREPORT_FIELDS + CHANGELOG. Then see "
        f"tests/architecture/test_face_contract.py: a new field also needs a "
        f"decision on every wire face."
    )
