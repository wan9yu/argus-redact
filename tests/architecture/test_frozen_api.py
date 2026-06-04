"""Layer 1 signature lock — v1.0 freeze candidate (v0.6.10).

Bumping any of these signatures is a Layer 1 breaking change and requires a
major version (v2.0+) per ``docs/architecture-layers.md``.

To regenerate after an intentional major-version bump, run::

    python -c "
    import inspect, argus_redact as a
    names = ['redact','restore','assess_risk','check_restore_safety','wipe_key','is_strategy_reversible','max_pseudonym_length']
    for n in names:
        print(repr(n), ':', repr(str(inspect.signature(getattr(a,n)))) + ',')
    "

and paste the output into ``FROZEN_SIGNATURES`` below.
"""
import inspect

import pytest

import argus_redact

FROZEN_SIGNATURES = {
    'redact': '(text: \'str\', *, key: \'dict | str | None\' = None, lang: \'str | list[str]\' = \'zh\', mode: \'str\' = \'fast\', salt: \'int | bytes | None\' = None, config: \'dict | str | None\' = None, names: \'list[str] | None\' = None, detailed: \'bool\' = False, report: \'bool\' = False, with_types: \'bool\' = False, profile: \'str | None\' = None, types: \'list[str] | None\' = None, types_exclude: \'list[str] | None\' = None, unified_prefix: \'str | None\' = None, _pre_detected: "\'list[PatternMatch] | None\'" = None)',
    'restore': "(text: 'str', key: 'dict[str, str] | str', *, aliases: 'dict[str, tuple[str, ...]] | None' = None, display_marker: 'str | None' = None) -> 'str'",
    'assess_risk': "(entities: 'list[dict]', lang: 'str' = 'zh') -> 'RiskResult'",
    'check_restore_safety': "(redacted: 'str', llm_output: 'str', key: 'dict[str, str]') -> 'list[str]'",
    'wipe_key': "(key: 'dict') -> 'None'",
    'is_strategy_reversible': "(strategy: 'str') -> 'bool'",
    'max_pseudonym_length': "(config: 'dict | None' = None) -> 'int'",
}

LAYER_1_EXPORTED = frozenset({
    "redact",
    "restore",
    "assess_risk",
    "check_restore_safety",
    "wipe_key",
    "is_strategy_reversible",
    "max_pseudonym_length",
    "SecurityWarning",
    "SessionStateError",
    "PseudonymPollutionError",
})


@pytest.mark.parametrize("name,expected", list(FROZEN_SIGNATURES.items()))
def test_layer_1_signatures_frozen(name, expected):
    fn = getattr(argus_redact, name)
    actual = str(inspect.signature(fn))
    assert actual == expected, (
        f"{name} signature changed — Layer 1 frozen contract violation.\n"
        f"  expected: {expected}\n"
        f"  actual:   {actual}\n"
        f"If intentional: bump to v2.0 and update FROZEN_SIGNATURES."
    )


FROZEN_EXCEPTION_PARENTS = {
    "SecurityWarning": "UserWarning",
    "SessionStateError": "RuntimeError",
    "PseudonymPollutionError": "ValueError",
}


def test_layer_1_exception_classes_unchanged():
    """Layer 1 exception class parent chains are frozen."""
    for cls_name, expected_parent in FROZEN_EXCEPTION_PARENTS.items():
        cls = getattr(argus_redact, cls_name)
        assert inspect.isclass(cls)
        parent = cls.__mro__[1].__name__
        assert parent == expected_parent, (
            f"{cls_name} parent changed from {expected_parent!r} to {parent!r} "
            f"— Layer 1 frozen contract violation. "
            f"If intentional: bump to v2.0 and update FROZEN_EXCEPTION_PARENTS."
        )


def test_layer_1_exports_present():
    """All Layer 1 symbols still present in argus_redact.__all__."""
    missing = LAYER_1_EXPORTED - set(argus_redact.__all__)
    assert not missing, f"Layer 1 symbols missing from __all__: {missing}"
