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
    fns = ['prompt_anchor', 'expand_aliases', 'register_pii_type']
    for n in fns:
        print(repr(n), ':', repr(str(inspect.signature(getattr(c, n)))) + ',')
    print('PIITypeDef:', sorted(f.name for f in dataclasses.fields(c.PIITypeDef)))
    print('PatternMatch:', sorted(f.name for f in dataclasses.fields(c.PatternMatch)))
    "
"""
import dataclasses
import inspect

import pytest

import argus_redact.compose as c

COMPOSE_SIGNATURES = {
    'prompt_anchor': "(key: 'dict', lang: 'str' = 'zh') -> 'str'",
    'expand_aliases': "(key: 'dict', lang: 'str' = 'zh') -> 'dict'",
    'register_pii_type': "(typedef: 'PIITypeDef') -> 'PIITypeDef'",
}

PIITYPEDEF_FIELDS = frozenset({
    '_patterns',
    'charset',
    'checksum',
    'counterexamples',
    'description',
    'examples',
    'faker',
    'faker_reserved',
    'format',
    'gdpr_special_category',
    'hipaa_phi_category',
    'label',
    'lang',
    'length',
    'mask_rule',
    'name',
    'pipl_articles',
    'prefixes',
    'sensitivity',
    'separators',
    'source',
    'strategy',
    'structure',
    'suffixes',
    'validate',
})

PATTERNMATCH_FIELDS = frozenset({
    'confidence',
    'end',
    'layer',
    'start',
    'text',
    'type',
})


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
