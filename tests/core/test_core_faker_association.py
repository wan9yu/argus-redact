"""Golden: the built-in (type, lang) → faker-name association lives in `_core`.

Phase A of the v0.7.5 `_core` cutover exposes the association that today is
discovered by introspecting the registered Python `faker_reserved` callable's
`__name__`. The SSOT for the association VALUES is the `register(PIITypeDef(...))`
calls in `specs/{zh,en,shared}.py`; this test pins the Rust `_core` table
against the LIVE registry so any drift (typo / missed pair / extra pair) fails.

`_core.builtin_faker_name(type, lang)` and `_core.builtin_faker_names()` are the
read surface Phase C will resolve built-in fakers through once the Python
callables are dropped.
"""

import argus_redact._core as _core
from argus_redact.specs import registry
from argus_redact.pure.replacer import _builtin_faker_names


def _builtin_typedefs():
    # Every registered typedef whose `faker_reserved` is a built-in (its
    # `__name__` is in the built-in name-set). Custom-faker typedefs (callable
    # defined outside the four built-in modules) are excluded — they are NOT
    # in the `_core` association table.
    builtin = _builtin_faker_names()
    for td in registry.list_types():  # registry iteration API (specs/registry.py)
        fr = getattr(td, "faker_reserved", None)
        if fr is not None and getattr(fr, "__name__", None) in builtin:
            yield td


def test_builtin_faker_name_matches_registry():
    n = 0
    for td in _builtin_typedefs():
        assert _core.builtin_faker_name(td.name, td.lang) == td.faker_reserved.__name__, (
            td.name,
            td.lang,
        )
        n += 1
    assert n >= 20  # all built-in (type,lang) pairs covered


def test_builtin_faker_names_matches_python_set():
    assert set(_core.builtin_faker_names()) == set(_builtin_faker_names())


def test_builtin_faker_name_unknown_returns_none():
    assert _core.builtin_faker_name("nonexistent_type", "zh") is None
